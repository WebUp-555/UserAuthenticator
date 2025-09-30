import { asyncHandler } from "../utils/AsyncHandler.js";
import {ApiError} from "../utils/ApiError.js";
import {User} from "../models/user.model.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import e from "express";

import jwt from "jsonwebtoken";
import mongoose from "mongoose";
const generateAccessTokenAndRefreshToken = async(userId) => {
  try{
       const user = await User.findById(userId)
      const accessToken= user.generateAccessToken()
      const refreshToken= user.generateRefreshToken()
      user.refreshToken=refreshToken
      await user.save({validateBeforeSave:false})
      return {accessToken,refreshToken}



  }catch(error){
     throw new ApiError(500,"Something went wrong while generating refresh and access tokens")
     
  }

}


const RegisterUser = asyncHandler(async (req, res) => {
    const { username, email, password, fullname } = req.body;
    if (!username || !email || !password || !fullname) {
        throw new ApiError(400, "All fields are required")
    }

    const existedUser= await User.findOne({$or:[{email},{username}]})
    if(existedUser){
        throw new ApiError(409,"User with this email or username already exists")
    }
    
const avatarLocalpath=req.files?.avatar?.[0]?.path;
  if(!avatarLocalpath){
      throw new ApiError(400,"Avatar is required")
    }
    
    const avatar = await uploadOnCloudinary(avatarLocalpath);



if(!avatar){
      throw new ApiError(400,"Avatar is required")
    }






    const user=await User.create({
        username,
        avatar: avatar.url,
        email,
        password,   
        fullname
    })
    if(!user){
        throw new ApiError(500,"User registration failed")
    }
    res.status(201).json(new ApiResponse(201,true,"User registered successfully",user))
})



const loginUser = asyncHandler(async (req, res) => {
    //req body -> data
    //username or email 
    //find the User
    //password check
    //access and refresh token
    //send cookie
    //return response

 const{username,email,password}=req.body
 console.log(email);
 if(!username && !email){
   throw new ApiError(400,"Username or email is required")
 }

   //Here is an alternative to the above logic discussion
   //if(!(username || email)){
   // throw new ApiError(400,"Username or email is required")
   //}

const user = await User.findOne({
  $or: [{ username }, { email }]
 })
  if(!user){
    throw new ApiError(404,"User does not exist")
  }
  
  const isPasswordValid= await user.isPasswordCorrect(password)
  if(!isPasswordValid){
    throw new ApiError(401,"Invalid user password")
  }

 const {accessToken, refreshToken} = await
  generateAccessTokenAndRefreshToken(user._id)

  const loggedInUser = await User.findById(user._id).
  select("-password -refreshToken")

  const options ={
    httpOnly:true,
    secure: true
  }
  return res
  .status(200).
  cookie("accessToken",accessToken,options)
  .cookie("refreshToken",refreshToken,options)
  .json(
    new ApiResponse(
      200,
      {
        user: loggedInUser,
        accessToken,
        refreshToken
      },
      "User logged in successfully"
    )
  )
  })

   const logoutUser = asyncHandler(async (req, res) => {
      await User.findByIdAndUpdate(req.user._id,{
        $unset:{
          refreshToken:1 //this removes the refresh token from the document
        }
      },{
        new:true
      })
      const options ={
      httpOnly:true,
       secure: true
  }
      return res
      .status(200)
      .clearCookie("accessToken",options)
      .clearCookie("refreshToken",options)
      .json(
        new ApiResponse(200, {}, "User logged out successfully")
      )
  })
  
  const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken
    if(!incomingRefreshToken){
      throw new ApiError(400,"unauthorized request")
    }


  try {
    const decodedToken=jwt.verify(incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET)
  
    const user= await User.findById(decodedToken?._id)
      if(!user){
        throw new ApiError(401,"Invalid refresh token") 
      }
       if(incomingRefreshToken !== user?.refreshToken){
        throw new ApiError(401,"Refresh token is expired or used")
  
  }
  
  const options ={
      httpOnly:true,
      secure: true
  }
   const {accessToken, newRefreshToken} = await generateAccessTokenAndRefreshToken(user._id)
   return res
    .status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",newRefreshToken,options)
    .json(
      new ApiResponse(
        200,
        {
          accessToken,
          refreshToken: newRefreshToken
        },
        "Access token refreshed successfully"
      )
    )
  } catch (error) {
    throw new ApiError(401,error?.message || "Invalid refresh token"
    )
  }


  })

  const changeCurrentPassword=asyncHandler(async(req,res)=>{
    const{oldPassword,newPassword}=req.body
    const user=await User.findById(req.user?._id)
    const isPasswordCorrect=await user.isPasswordCorrect(oldPassword)
    if(!isPasswordCorrect){
      throw new ApiError(400,"Invalid old password")
    }
     user.password = newPassword
     await user.save({validateBeforeSave:false})

     return res
     .status(200)
     .json(new ApiResponse(200,{},"Password changed Sucessfully "))

  })

  const getCurrentUser=asyncHandler(async(req,res)=>{
    return res
    .status(200)
    .json(new ApiResponse(200, req.user, "current user fetched successfully"));
  })


const updateAccountDetails=asyncHandler(async(req,res)=>{
  const{fullname,email}=req.body
   
  if(!fullname || !email){
    throw new ApiError(400,"All fields are required")
  }
   const user= User.findByIdAndUpdate(
    req.user?._id,
    { $set: { fullname, email: email } },
    { new: true }
  ).select("-password")
  return res
  .status(200)
  .json(new ApiResponse (200,user,"Account details updated successfully"))

})

const updateUserAvatar = asyncHandler(async(req,res)=>
{
  const avatarLocalPath=req.file?.path 

  if(!avatarLocalPath){
    throw new ApiError(400,"Avatar file is missing")

  }
   const avatar=await uploadOnCloudinary(avatarLocalPath)
   if(!avatar.url){
    throw new ApiError(400,"Error while uploading on avatar")
   }
   const user=await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set:{
        avatar:avatar.url
      }
    },
    {new:true}

   ).select("-password")
   return res
   .status(200)
   .json(new ApiResponse(200, user, "Avatar updated successfully"))

})


export {
    RegisterUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar
}
