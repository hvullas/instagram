package main

import (
	"backend/cron"
	"backend/db"
	"backend/handlers"
	"log"

	"os"

	"net/http"

	_ "image/jpeg"
	_ "image/png"

	_ "github.com/lib/pq"
)

const MB = 1 << 20

func main() {

	db.ConnectDB()
	defer db.DB.Close()

	//create profilePhoto directory if not exists
	if err := os.MkdirAll("./profilePhoto", os.ModePerm); err != nil {
		log.Fatal("Error creating posts directory", err)
	}

	//create posts directory if not exists
	if err := os.MkdirAll("./posts", os.ModePerm); err != nil {
		log.Fatal("Error creating posts directory", err)
	}

	//create stories directory if not exists
	if err := os.MkdirAll("./stories", os.ModePerm); err != nil {
		log.Fatal("Error creating posts directory", err)
	}

	cron.Run()

	http.HandleFunc("/newUserInfo", handlers.NewUser)

	//user authorisation
	http.HandleFunc("/login", handlers.Login)

	//handle function to upload users' display picture //ullas
	http.HandleFunc("/updateUserDisplayPic", handlers.UpdateUserDP)

	//func to get profilePic
	http.HandleFunc("/getProfilePic/profilePhoto/", handlers.DisplayDP)

	//handle func to serve posts
	http.HandleFunc("/download/posts/", handlers.DownloadPosts)

	//to post media to instagram
	http.HandleFunc("/postMediaInfo", handlers.PostMedia)

	//handle func to upload user posts
	http.HandleFunc("/postMediaPath", handlers.PostMediaPath)

	//to get all posts of users
	http.HandleFunc("/getAllPosts", handlers.AllPosts)

	// handle function to like 		a post
	http.HandleFunc("/likePost", handlers.LikePosts)

	//handle func to comment a post based on postid
	http.HandleFunc("/commentPost", handlers.CommentPost)

	//handle func to get all comments of a post based on postId
	http.HandleFunc("/getAllComments", handlers.AllComments)

	//handle function to follow(me following other)
	http.HandleFunc("/follow", handlers.FollowOthers)

	//handle function to list followers of a user
	http.HandleFunc("/followers", handlers.GetFollowers)

	//pending follow requests
	http.HandleFunc("/getFollowRequests", handlers.PendingFollowRequests)

	//response to follow requests
	http.HandleFunc("/respondingRequest", handlers.RespondingFollowRequests)

	//handleFunc to remove follower
	http.HandleFunc("/removeFollower", handlers.RemoveFollowers)

	//handle func to get list of users me following
	http.HandleFunc("/following", handlers.GetFollowing)

	//handle function to update bio in profile
	http.HandleFunc("/updateBio", handlers.UpdateBio)

	//get profile
	http.HandleFunc("/userProfile", handlers.UpdateProfile)

	//to save a post
	http.HandleFunc("/savePost", handlers.SavePosts)

	//handle function to get posts using post_id
	http.HandleFunc("/getpost/", handlers.GetPost)

	//handle func to get all saved posts of a user
	http.HandleFunc("/savedposts", handlers.SavedPosts)

	//delete user
	http.HandleFunc("/deleteAccount", handlers.DeleteAccount)

	//remove saved post

	http.HandleFunc("/removeSavedPost", handlers.RemoveSavedPost)

	//turnoff commenting

	http.HandleFunc("/turnoffComments", handlers.TurnOffComments)

	//turnon commenting

	http.HandleFunc("/turnonComments", handlers.TurnONComments)

	//hide like count
	http.HandleFunc("/hidelikeCount", handlers.HideLikeCount)

	//show like count
	http.HandleFunc("/showlikeCount", handlers.ShowLikeCount)

	//delete comment
	http.HandleFunc("/deleteComment", handlers.DeleteComment)

	//api for searching users

	http.HandleFunc("/searchAccounts", handlers.SearchAccounts)

	//search for hashtags
	http.HandleFunc("/searchHashtag", handlers.SearchHashtag)

	//handle func to upload story info
	http.HandleFunc("/uploadStoryInfo", handlers.UploadStory)

	//handle func to upload story media
	http.HandleFunc("/uploadStoryPath", handlers.UploadStoryPath)

	//download story

	http.HandleFunc("/getStory", handlers.GetStory)

	//download story api
	//handle func to serve posts
	http.HandleFunc("/download/stories/", handlers.DownloadStory)

	//delete story
	http.HandleFunc("/deleteStory", handlers.DeleteStory)

	//check post upload status
	http.HandleFunc("/postUploadStatus", handlers.PostUploadStatus)

	//check story upload status
	http.HandleFunc("/storyUploadStatus", handlers.StoryUploadStatus)

	//get active stories for a user
	http.HandleFunc("/getActiveStories", handlers.AllActiveStories)

	//updates story seen status
	http.HandleFunc("/updateStorySeenStatus", handlers.UpdateStorySeenStatus)

	http.ListenAndServe(":3000", nil)

}
