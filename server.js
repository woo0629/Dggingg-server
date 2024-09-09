const express = require("express");
const bodyParser = require("body-parser");
const app = express();
const path = require("path");
const cors = require("cors");
const passport = require("passport");
const jwt = require("jsonwebtoken");
const LocalStrategy = require("passport-local").Strategy;
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
require("dotenv").config();
const { MongoClient } = require("mongodb");
const { ObjectId } = require("mongodb");
const { S3Client } = require("@aws-sdk/client-s3");
const multer = require("multer");
const multerS3 = require("multer-s3");
const frontendUrl = process.env.FRONTEND_URL;
const url = process.env.DB_URL;
const client = new MongoClient(url, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  tls: true,
});

const corsOptions = {
  origin: [
    "https://web-digging-fr-m0e1rvdd84ededf2.sel4.cloudtype.app",
    "https://port-0-digging-server-m0e1rvdd84ededf2.sel4.cloudtype.app",
    "http://localhost:8080",
  ],
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
console.log("cors 설정 완료", corsOptions);
app.options("*", cors(corsOptions));

const s3 = new S3Client({
  region: process.env.S3_BUCKET_REGION,
  credentials: {
    accessKeyId: process.env.S3_KEY,
    secretAccessKey: process.env.S3_SECRET,
  },
});

//aws s3로 이미지 저장
const upload = multer({
  storage: multerS3({
    s3: s3,
    bucket: process.env.S3_BUCKET_NAME,
    key: function (req, file, cb) {
      cb(null, Date.now().toString()); //업로드시 파일명 변경가능
    },
  }),
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(passport.initialize());

let db;
client
  .connect()
  .then(() => {
    console.log("DB 연결 성공");
    db = client.db("digging");
    // 추가적인 데이터베이스 작업을 여기에서 수행합니다.
  })
  .catch((err) => {
    console.error("DB 연결 실패:", err);
  });
// .finally(() => {
//   // 클라이언트를 종료하는 부분
//   client
//     .close()
//     .then(() => console.log("DB 클라이언트 종료"))
//     .catch((err) => console.error("DB 클라이언트 종료 실패:", err));
// });

// app.use(express.static(path.join(__dirname, "pandaproject/build")));

app.get("/", (req, res) => {
  res.redirect(frontendUrl);
});

passport.use(
  new LocalStrategy(async (EnterId, EnterPw, cb) => {
    let result = await db.collection("user").findOne({ username: EnterId });
    if (!result) {
      console.log("localstrategy-if문 아이디가 없으면");
      return cb(null, false, { message: "아이디 DB에 없음" });
    }
    if (result.password == EnterPw) {
      console.log("localstrategy-if문 아이디가 있고 패스워드가 일치하면 통과");
      return cb(null, result);
    } else {
      return cb(null, false, { message: "비밀번호 불일치" });
    }
  })
);
function generateToken(user) {
  return jwt.sign(
    {
      id: user._id,
      username: user.username,
      address: user.address,
      subaddress: user.subaddress,
      email: user.email,
    },
    process.env.JWT_SECRET_KEY
  );
}
app.post("/login", (req, res, next) => {
  passport.authenticate("local", { session: false }, (err, user, info) => {
    console.log("passport.authenticate 1 번");
    console.log("info", info);
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(401).json({ error: info.message });
    console.log(
      "passport.authenticate 2 번 서버에러,유저가 정보가있으면 토큰을 담아서 넘겨줘라 "
    );
    const token = generateToken(user);
    const expiration = new Date(Date.now() + 60 * 60 * 1000); // 1시간
    res.json({ token, expiration: expiration.getTime() });
    console.log("Server Log:", { token, expiration });
  })(req, res, next);
});

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme("Bearer"),
  secretOrKey: process.env.JWT_SECRET_KEY,
};

passport.use(
  new JwtStrategy(jwtOptions, async (jwtPayload, cb) => {
    const userId = jwtPayload.id;
    console.log("userId", userId);

    try {
      const user = await db
        .collection("user")
        .findOne({ _id: new ObjectId(userId) });
      console.log("마지막검증");
      if (user) {
        console.log("유저를 찾았음:", user);
        return cb(null, user);
      } else {
        console.log("유저를 찾을 수 없음");
        return cb(null, false, { message: "토큰 유효성 검증 실패" });
      }
    } catch (err) {
      console.error("DB 조회 중 에러:", err);
      return cb(err, false);
    }
  })
);
app.get(
  "/verify",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    res.json({ message: "토큰이 유효합니다." });
  }
);

// const verifyToken = (req, res, next) => {
//   const token =
//     req.headers.authorization && req.headers.authorization.split(" ")[1];

//   if (!token) {
//     return res.status(401).json({ error: "토큰이 없습니다." });
//   }

//   jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
//     if (err) {
//       return res.status(401).json({ error: "토큰이 유효하지 않습니다." });
//     }

//     // 토큰이 유효하면 다음 미들웨어로 넘깁니다.
//     req.user = decoded;
//     next();
//   });
// };

// app.get("/protected", verifyToken, (req, res) => {
//   res.json({ message: "토큰이 유효합니다.", user: req.user });
// });

app.post("/signup", async (req, res) => {
  const userData = req.body;
  console.log(userData);

  await db.collection("user").insertOne({
    username: userData.username,
    email: userData.email,
    password: userData.password,
    address: userData.address,
    subaddress: userData.subaddress,
  });
  res.json({ message: "ok" });
});

app.get("/category/:id", async (req, res) => {
  const result = await db.collection(req.params.id).find().toArray();
  res.json({ result: result });
});

app.post("/register/:id", upload.single("image"), async (req, res) => {
  const currentDate = new Date();
  req.body.date = currentDate.toISOString();

  await db.collection(req.params.id).insertOne({
    id: req.body.id,
    username: req.body.username,
    address: req.body.address,
    title: req.body.title,
    content: req.body.content,
    price: req.body.price,
    date: req.body.date,
    image: req.file ? req.file.location : "",
  });
  res.json({ message: "ok" });
});

app.get("/:id/search", async (req, res) => {
  const result = await db
    .collection(req.params.id)
    .find({ title: { $regex: req.query.val } })
    .toArray();
  console.log(result);
  res.json({ result: result });
});

app.delete("/category/:id/detail", async (req, res) => {
  try {
    const objId = req.body._id;
    await db.collection(req.params.id).deleteOne({ _id: new ObjectId(objId) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "서버 오류" });
  }
  res.send("삭제완료");
});

app.post("/edit/:id", upload.single("image"), async (req, res) => {
  let objId = new ObjectId(req.body._id);

  // 현재 데이터에서 기존 이미지 URL을 가져옵니다.
  const existingItem = await db
    .collection(req.params.id)
    .findOne({ _id: objId });
  const currentImage = existingItem ? existingItem.image : null;

  // 새 이미지를 업로드하지 않은 경우 기존 이미지 URL을 유지합니다.
  const newImage = req.file ? req.file.location : currentImage;
  console.log("existingItem", existingItem);
  console.log("newImage", newImage);
  await db.collection(req.params.id).updateOne(
    { _id: objId },
    {
      $set: {
        id: req.body.id,
        username: req.body.username,
        title: req.body.title,
        content: req.body.content,
        price: req.body.price,
        image: newImage,
      },
    }
  );
  res.json({ message: "ok" });
});

app.post("/comment", async (req, res) => {
  await db.collection("comment").insertOne({
    contentId: req.body.contentId,
    contentWriterId: req.body.contentWriterId,
    contentWriterName: req.body.contentWriterName,
    loginName: req.body.loginName,
    loginId: req.body.loginId,
    comment: req.body.comment,
  });
  res.json({ message: "ok" });
});

app.get("/categoryComment", async (req, res) => {
  console.log("categoryComment", new Date());
  const result = await db
    .collection("comment")
    .find({ contentId: req.query.id })
    .toArray();
  console.log("result", result.length);
  res.json({ result: result });
});

app.delete("/commentdelete", async (req, res) => {
  console.log(req.query.id);
  try {
    const objId = req.query.id;
    await db.collection("comment").deleteOne({ _id: new ObjectId(objId) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "서버 오류" });
  }
  res.json({ message: "ok" });
});

app.post("/logout", (req, res) => {
  // 클라이언트 측에서의 토큰 및 만료 시간 삭제
  res.clearCookie("token");
  res.clearCookie("tokenExpiration");

  // 또는 클라이언트 측에서 사용하는 로컬 스토리지의 값 삭제
  localStorage.removeItem("token");
  localStorage.removeItem("tokenExpiration");

  res.json({ message: "로그아웃 성공" });
});

app.get(
  "/protected",
  passport.authenticate("jwt", { session: false }),
  (res) => {
    res.json({ message: "Protected resource" });
  }
);

app.get(
  "/mypage",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    res.json({
      id: req.user._id,
      username: req.user.username,
      email: req.user.email,
      address: req.user.address,
      subaddress: req.user.subaddress,
    });
  }
);

app.get("/board", async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const pageSize = 10;
    const skip = (page - 1) * pageSize;
    const { searchTerm, tag } = req.query;
    console.log(tag);
    console.log(searchTerm);
    // Build the query based on whether a search term is provided
    let query = {};
    if (searchTerm) {
      query.title = { $regex: new RegExp(searchTerm, "i") };
    }

    console.log(tag);
    if (tag) {
      query.tag = tag;
    }

    const result = await db
      .collection("board")
      .find(query)
      .skip(skip)
      .limit(pageSize)
      .toArray();

    res.json({ result });
  } catch (error) {
    console.error("게시판 데이터를 가져오는 중 에러 발생:", error);
    res.status(500).json({
      message: "게시판 데이터를 가져오는 중 에러가 발생했습니다.",
    });
  }
});
app.post("/board", async (req, res) => {
  const boardData = req.body;
  const currentDate = new Date();
  boardData.date = currentDate.toISOString();

  await db.collection("board").insertOne({
    id: boardData.id,
    title: boardData.title,
    content: boardData.content,
    writer: boardData.writer,
    views: boardData.views,
    date: boardData.date,
    tag: boardData.tag,
    comments: [],
  });
  res.json({ message: "ok" });
});

app.post("/board_detail/:postId", async (req, res) => {
  const postId = req.params.postId;
  const { action } = req.body;
  const currentDate = new Date();

  console.log("action", action);
  if (action === "addReply") {
    console.log("addReply", action);
    const commentListData = req.body;
    const parentId = commentListData.parentId;
    commentListData.date = currentDate.toISOString();

    //자식 데이터
    try {
      const parentComment = await db.collection("comment123").findOne({
        _id: new ObjectId(parentId),
      });
      console.log("parentComment", parentComment);
      await db.collection("comment123").insertOne({
        parentId: commentListData.parentId,
        postId: commentListData.postId,
        writerId: commentListData.writerId,
        writer: commentListData.writer,
        content: commentListData.content,
        date: commentListData.date,
        depth: parentComment.depth + 1,
      });

      res.json({ message: "ok" });
    } catch (error) {
      console.error("Error adding comment:", error.message);
      res.status(500).json({ message: "Internal server error" });
    }
  }
  if (action === "commentsubmit") {
    console.log("commentsubmit,", action);
    const commentdata = req.body;
    console.log("commentdata", commentdata);
    commentdata.date = currentDate.toISOString();
    //부모 데이터
    try {
      await db.collection("comment123").insertOne({
        postId: commentdata.postId,
        writerId: commentdata.writerId,
        writer: commentdata.writer,
        content: commentdata.content,
        date: commentdata.date,
        depth: commentdata.depth,
      });

      res.json({ message: "ok" });
    } catch (error) {
      console.error("Error adding comment:", error.message);
      res.status(500).json({ message: "Internal server error" });
    }
  }
  if (action === "handlePostClick") {
    console.log("handlePostClick", action);
    try {
      // 클라이언트에서 전달한 postId를 사용하여 해당 게시물을 찾음
      const post = await db
        .collection("board")
        .findOne({ _id: new ObjectId(postId) });
      if (!post) {
        return res.status(404).json({ message: "Post not found" });
      }
      const result = await db.collection("board").updateOne(
        { _id: new ObjectId(postId) },
        { $inc: { views: 1 } } // views를 1 증가시킴
      );
      if (result.matchedCount === 1) {
        res.json({ message: "OK" });
      } else {
        res.status(404).json({ message: "Post not found" });
      }
    } catch (error) {
      console.error("Error updating views:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
});
app.get("/board_detail/:postId", async (req, res) => {
  const postId = req.params.postId;
  try {
    // 클라이언트에서 전달한 postId를 사용하여 해당 게시물을 찾음
    const post = await db
      .collection("board")
      .findOne({ _id: new ObjectId(postId) });

    const comments = await db
      .collection("comment123")
      .find({ postId: postId })
      .toArray();

    if (!post) {
      return res.status(404).json({ message: "Post not found" });
    }

    // 게시물과 댓글을 하나의 응답 객체로 합침
    const responseData = {
      post: post,
      comments: comments,
    };

    res.json(responseData);
  } catch (error) {
    console.error("Error fetching post detail:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.put("/board_edit/:postId", async (req, res) => {
  const { postId } = req.params;
  const updatedData = req.body;
  console.log("postId", postId);
  console.log("updatedData", updatedData);
  try {
    await db.collection("board").updateOne(
      { _id: new ObjectId(postId) },
      {
        $set: {
          title: updatedData.title,
          content: updatedData.content,
          tag: updatedData.tag,
        },
      }
    );

    res.json({ message: "ok" });
  } catch (error) {
    console.error("수정 에러:", error.message);
    res.status(500).json({ error: "서버 에러" });
  }
});
app.delete("/board_detail/:postId", async (req, res) => {
  const { postId } = req.params;
  const { action, commentId } = req.body;

  try {
    if (action === "deleteComment") {
      console.log("test");
      // 댓글 삭제 처리
      const result = await db.collection("comment123").deleteOne({
        _id: new ObjectId(commentId),
        postId: postId,
      });

      if (result.deletedCount === 1) {
        res.json({ message: "댓글 삭제 성공" });
      } else {
        res.status(404).json({ error: "댓글을 찾을 수 없습니다." });
      }
    } else if (action === "deletePost") {
      // 게시물 삭제 처리
      const result = await db.collection("board").deleteOne({
        _id: new ObjectId(postId),
      });

      if (result.deletedCount === 1) {
        res.json({ message: "게시물 삭제 성공" });
      } else {
        res.status(404).json({ error: "게시물을 찾을 수 없습니다." });
      }
    } else {
      res.status(400).json({ error: "잘못된 요청입니다." });
    }
  } catch (error) {
    console.error("삭제 에러:", error.message);
    res.status(500).json({ error: "서버 에러" });
  }
});

app.get("/manager/userInfo", async (req, res) => {
  try {
    const users = await db
      .collection("user")
      .find({}, { username: 1, alert: 1 }) // 필드 지정
      .toArray();
    res.json(users);
  } catch (error) {
    console.error("Error fetching user information:", error);
    res.status(500).json({ error: "Failed to fetch user information" });
  }
});

app.patch("/manager/userInfo/:userId", async (req, res) => {
  try {
    const userId = req.params.userId;
    const { alert } = req.body;

    // MongoDB의 user 컬렉션에서 해당 userId를 가진 사용자의 정보를 업데이트합니다.
    const result = await db.collection("user").updateOne(
      { _id: new ObjectId(userId) }, // ObjectId로 변환하여 해당 userId를 가진 사용자를 찾습니다.
      { $set: { alert: alert } } // alert 필드를 업데이트합니다.
    );

    if (result.modifiedCount === 1) {
      res.json({ message: "Alert field updated successfully" });
    } else {
      res.status(400).json({ error: "Failed to update alert field" });
    }
  } catch (error) {
    console.error("Error updating alert field:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/manager/alerts/:id", async (req, res) => {
  console.log("manager/alerts" + new Date());
  try {
    const Id = req.params.id;
    console.log(Id);
    const alerts = await db
      .collection("user")
      .findOne({ _id: new ObjectId(Id) });
    console.log(alerts);
    res.json(alerts);
  } catch (error) {
    console.error("Error fetching alerts:", error);
    res.status(500).json({ error: "Failed to fetch alerts" });
  }
});

//이거 맨밑으로
app.get("*", function (req, res) {
  res.redirect(frontendUrl);
});

const port = process.env.SERVER_URL || 8080;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
