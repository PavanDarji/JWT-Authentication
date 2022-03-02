import express from "express";
const router = express.Router();
import UserController from "../controller/userController.js";
import checkUserAuth from "../middlware/auth-middlewaare.js";

//Route  level Middleware - To Protect Route
router.use('/changePassword', checkUserAuth)
router.use('/loggedUser', checkUserAuth)



// Public Routes

router.post('/register', UserController.userRegistration)
router.post('/login', UserController.userLogin)
router.post('/send-reset-password-email', UserController.sendUserPasswordResetEmail)
router.post('/reset-password/:id/:token', UserController.userPasswordReset)


// Protected Routes
router.post('/changePassword', UserController.chnageUserPassword)
router.get('/loggedUser', UserController.loggedUser)


export default router