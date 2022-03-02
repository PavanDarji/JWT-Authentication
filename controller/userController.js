import UserModel from '../model/user.js'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken';
import transporter from '../config/emailConfig.js';


class UserController {

    // User Register Function


    static userRegistration = async (req, res) => {
        let { name, email, password, cpassword, tc } = req.body
        const user = await UserModel.findOne({ email: email })
        if (user) {
            res.send({ "status": "failed", "message": "Email Already exists" })
        }
        else {
            if (name && email && password && cpassword && tc) {
                if (password === cpassword) {
                    try {
                        let salt = await bcrypt.genSalt(10)
                        let hashPassword = await bcrypt.hash(password, salt)
                        let data = new UserModel({
                            name: name,
                            email: email,
                            password: hashPassword,
                            tc: tc
                        });
                        let result = await data.save();

                        // JWT Token 

                        const saved_user = await UserModel.findOne({ email: email })
                        //Generate JWT Token
                        const token = jwt.sign({ userID: saved_user._id }, process.env.JWT_SECRET_KEY, { expiresIn: '45m' })


                        // res.send(result);
                        res.send({ "status": "success", "message": "Registration Successfull...", "token": token });

                    } catch (error) {
                        // console.log(error);
                        res.send({ "status": "failed", "message": "Unable to Register" });

                    }
                }
                else {
                    res.send({ "status": "failed", "message": "Password and Confirm Password Does Not Match" });
                }
            }
            else {
                res.send({ "status": "failed", "message": "All Fields are required" });
            }
        }
    }

    // User Login Function

    static userLogin = async (req, res) => {
        try {

            const { email, password } = req.body
            if (email && password) {
                const user = await UserModel.findOne({ email: email })
                if (user != null) {
                    const isMatch = await bcrypt.compare(password, user.password)
                    if ((user.email === email) && isMatch) {

                        // Genrate JWT 
                        const token = jwt.sign({ userID: user._id }, process.env.JWT_SECRET_KEY, { expiresIn: '45m' })


                        res.send({ "status": "success", "message": "Login Successfull...", "token": token });

                    }
                    else {
                        res.send({ "status": "failed", "message": "Email or Password is not Valid" });

                    }
                }
                else {
                    res.send({ "status": "failed", "message": "Your are not Register User" });

                }
            }
            else {
                res.send({ "status": "failed", "message": "All Fields are required" });

            }

        } catch (error) {
            // console.log(error);
            res.send({ "status": "failed", "message": "Unable to Login" });

        }
    }

    // change password 

    static chnageUserPassword = async (req, res) => {
        const { password, cpassword } = req.body
        if (password && cpassword) {
            if (password !== cpassword) {
                res.send({ "status": "failed", "message": "New Password and Confirm Password Does Not Match" });

            }
            else {
                const salt = await bcrypt.genSalt(10)
                const newhashPassword = await bcrypt.hash(password, salt)
                await UserModel.findByIdAndUpdate(req.user._id, {
                    $set: {
                        password: newhashPassword
                    }
                })
                res.send({ "status": "success", "message": "Password Change Successfull..." });


            }
        }
        else {
            res.send({ "status": "failed", "message": "All Fields are required" });

        }
    }


    // Get Logged In User Data

    static loggedUser = async (req, res) => {
        res.send({ "user": req.user })
    }


    // Reset / Forgot Password
    // send email code 

    static sendUserPasswordResetEmail = async (req, res) => {
        const { email } = req.body
        if (email) {
            const user = await UserModel.findOne({ email: email })

            if (user) {
                const secret = user._id + process.env.JWT_SECRET_KEY
                const token = jwt.sign({ userID: user._id }, secret, {
                    expiresIn: '15m'
                })
                const link = `http://127.0.0.1:3000/api/user/reset/${user._id}/${token}`
                // console.log(link);

                //send email
                let info = await transporter.sendMail({
                    from: process.env.EMAIL_FROM,
                    to: user.email,
                    subject: "Password Reset Link",
                    html: `<a href=${link}>Click Here</a> to Reset Your Password`
                })
                //

                res.send({ "status": "success", "message": "Password Reset Link Sent in Email.....Please Check Your Email", "info": info });


            }
            else {
                res.send({ "status": "failed", "message": "Email Does not exists" });

            }
        } else {
            res.send({ "status": "failed", "message": "Email Fields are required" });

        }
    }

    // Reset / forgot password

    static userPasswordReset = async (req, res) => {
        const { password, cpassword } = req.body
        const { id, token } = req.params
        const user = await UserModel.findById(id)
        const new_secret = user._id + process.env.JWT_SECRET_KEY
        try {
            jwt.verify(token, new_secret)
            if (password && cpassword) {
                if (password !== cpassword) {
                    res.send({ "status": "failed", "message": "Password And Confirm Password Not Match" });

                }
                else {
                    const salt = await bcrypt.genSalt(10)
                    const newhashPassword = await bcrypt.hash(password, salt)
                    await UserModel.findByIdAndUpdate(user._id, {
                        $set: {
                            password: newhashPassword
                        }
                    })
                    res.send({ "status": "success", "message": "Password Reset Successfull..." });

                }
            } else {
                res.send({ "status": "failed", "message": "All Fields are Required" });

            }
        } catch (error) {
            console.log(error);
            res.send({ "status": "failed", "message": "Invalid Token" });

        }
    }
}

export default UserController