import {
    RegisterUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar
} from "../controllers/user.control.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";
import express, { Router } from "express"
import { upload } from "../middlewares/multer.middleware.js";

const router = express.Router();

router.post("/register", upload.fields([
    { name: "avatar", maxCount: 1 }
]), RegisterUser);
router.post("/login", loginUser);
router.post("/logout", verifyJWT, logoutUser);
router.post("/refresh-token", refreshAccessToken);
router.post("/change-password", verifyJWT, changeCurrentPassword);
router.get("/current-user", verifyJWT, getCurrentUser);
router.put("/update-account", verifyJWT, updateAccountDetails);
router.put("/update-avatar", verifyJWT, upload.single("avatar"), updateUserAvatar);

export default router;
