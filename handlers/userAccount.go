package handlers

import (
	"backend/db"
	"backend/models"
	"backend/src"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var login models.LoginCred
	err := json.NewDecoder(r.Body).Decode(&login)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusMethodNotAllowed)
		return
	}
	//auth
	var passwordHash string
	err = db.DB.QueryRow("SELECT password FROM users WHERE user_name=$1", login.UserName).Scan(&passwordHash)
	if err != nil {
		panic(err)
	}
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(login.Password))
	if err == nil {
		fmt.Fprintln(w, true)
	}
	if err != nil {
		fmt.Fprintln(w, "Invalid password")
		return
	}

}

func NewUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var userdata models.NewUser
	err := json.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		fmt.Fprintln(w, "Error decoding Request body")
		return
	}

	if err = src.ValidateNewUserInput(&userdata); err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusBadRequest)
		return
	}

	//check for duplication of user name
	userExists := `SELECT user_name FROM users WHERE user_name=$1`
	var usernameexits string
	err = db.DB.QueryRow(userExists, userdata.UserName).Scan(&usernameexits)
	// if err != nil {
	// 	panic(err)
	// }
	if usernameexits == userdata.UserName {
		fmt.Fprintln(w, "User Name already exists. Try another user name")
		return
	}

	//check for duplication of email address
	userEmailExists := `SELECT email FROM users WHERE email=$1`
	var emailexits string
	err = db.DB.QueryRow(userEmailExists, userdata.Email).Scan(&emailexits)
	// if err != nil {
	// 	panic(err)
	// }
	if emailexits == userdata.Email {
		fmt.Fprintln(w, "Account with this email already exists")
		return
	}

	//check for duplication of phone number
	userCellExists := `SELECT phone_number FROM users WHERE phone_number=$1`
	var numberExists string
	err = db.DB.QueryRow(userCellExists, userdata.PhoneNumber).Scan(&numberExists)
	// if err != nil {
	// 	panic(err)
	// }
	if numberExists == userdata.PhoneNumber {
		fmt.Fprintln(w, "Account with this phone number already exists")
		return
	}

	//hashing the password before storing to the database
	pass := []byte(userdata.Password)

	// Hashing the password
	hash, err := bcrypt.GenerateFromPassword(pass, 8)
	if err != nil {
		panic(err)
	}

	userdata.DisplayPicture = "profilePhoto/DefaultProfilePicture.jpeg"

	regUserInfo := `INSERT INTO users (user_name,password,email,phone_number,dob,bio,private,display_pic,name) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING user_id`
	var userID models.UserID
	err = db.DB.QueryRow(regUserInfo, userdata.UserName, string(hash), userdata.Email, userdata.PhoneNumber, userdata.DOB, userdata.Bio, userdata.Private, userdata.DisplayPicture, userdata.Name).Scan(&userID.UserId)
	if err != nil {
		panic(err)

	}

	json.NewEncoder(w).Encode(userID)

}
func DisplayDP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	url := fmt.Sprint(r.URL)

	_, file := path.Split(url)

	imagePath := "./profilePhoto/" + file
	imagedata, err := ioutil.ReadFile(imagePath)

	if err != nil {
		http.Error(w, "Couldn't read the file", http.StatusInternalServerError)
		return
	}

	ext := strings.ToLower(filepath.Ext(file))

	contentType := models.GetExtension(ext)

	if contentType == "" {
		http.Error(w, "Unsupported file format", http.StatusUnsupportedMediaType)
		return
	}

	w.Header().Set("Content-Type", contentType)

	_, err = w.Write(imagedata)
	if err != nil {
		http.Error(w, "failed to write image data to response", http.StatusInternalServerError)
		return
	}

}
func UpdateUserDP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// set parse data limit
	r.Body = http.MaxBytesReader(w, r.Body, 5*MB)
	err := r.ParseMultipartForm(5 * MB) // 10 MB
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusMethodNotAllowed)
		return
	}

	// Get the file from the request
	file, fileHeader, err := r.FormFile("display_picture")
	if err != nil {
		http.Error(w, "Missing formfile", http.StatusBadRequest)
		return
	}

	//get cleaned file name
	s := regexp.MustCompile(`\s+`).ReplaceAllString(fileHeader.Filename, "")
	time := fmt.Sprintf("%v", time.Now())
	s = regexp.MustCompile(`\s+`).ReplaceAllString(time, "") + s

	jsonData := r.FormValue("user_id")
	var userId models.UserID
	err = json.Unmarshal([]byte(jsonData), &userId)
	if err != nil {
		http.Error(w, "Error unmarshalling JSON data", http.StatusInternalServerError)
		return
	}
	var deleteUrl string
	db.DB.QueryRow("SELECT display_pic FROM users WHERE user_id=$1", userId.UserId).Scan(&deleteUrl)
	filelocation := "./" + deleteUrl

	if filelocation != "./profilePhoto/DefaultProfilePicture.jpeg" {
		os.Remove(filelocation)
	}

	//check for file allowed file format
	match, _ := regexp.MatchString("^.*\\.(jpg|JPG|png|PNG|JPEG|jpeg|bmp|BMP)$", s)
	if !match {
		fmt.Fprintln(w, "Only JPG,JPEG,PNG,BMP formats are allowed for upload")
		return
	} else {
		//check for the file size
		if size := fileHeader.Size; size > 8*MB {
			http.Error(w, "File size exceeds 8MB", http.StatusInternalServerError)
			return
		}
	}

	// Create a new file on the server(folder)
	fileName := s

	dst, err := os.Create(filepath.Join("./profilePhoto", fileName))
	if err != nil {
		http.Error(w, "Unable to create file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// Copy the file data to the directory
	_, err = io.Copy(dst, file)
	if err != nil {
		http.Error(w, "Unable to write file", http.StatusInternalServerError)
		return
	}

	filePath := filepath.Join("./profilePhoto", fileName)

	// image, _, err := image.DecodeConfig(file)
	// if err != nil {
	// 	panic(err)
	// }

	// if image.Height < 150 && image.Width < 150 {
	// 	http.Error(w, "Image resolution too low", http.StatusInternalServerError)
	// 	e := os.Remove(filePath)
	// 	if e != nil {
	// 		panic(e)
	// 	}

	// 	return
	// }

	urlpart1 := "http://localhost:3000/getProfilePic/"

	var retrivedUrl string

	var dpURL models.GetProfilePicURL
	err = db.DB.QueryRow("UPDATE users SET display_pic=$1 WHERE user_id=$2 RETURNING display_pic", filePath, userId.UserId).Scan(&retrivedUrl)
	if err != nil {
		panic(err)
	}

	dpURL.PicURL = urlpart1 + retrivedUrl
	err = json.NewEncoder(w).Encode(dpURL)
	if err != nil {
		panic(err)
	}

}
func FollowOthers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not valid", http.StatusMethodNotAllowed)
		return
	}
	var x models.Follow
	err := json.NewDecoder(r.Body).Decode(&x)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusMethodNotAllowed)
		return
	}

	if x.MyId == 0 || x.Following == 0 {
		fmt.Fprint(w, "Invalid IDs or missing fields")
		return
	}

	var private bool
	err = db.DB.QueryRow("SELECT private FROM users WHERE user_id=$1", x.Following).Scan(&private)
	if err != nil {
		panic(err)
	}

	if private == true {
		_, err = db.DB.Query("INSERT INTO follower(user_id,follower_id,accepted) VALUES($1,$2,$3)", x.MyId, x.Following, false)
		if err != nil {
			_, err = db.DB.Query("DELETE FROM follower WHERE follower_id=$1", x.Following)
			if err != nil {
				panic(err)
			}
			fmt.Fprintln(w, "removed follow request")
			return
		}
		fmt.Fprintln(w, "Follow request pending")
		var follow models.FollowStatus
		follow.FollowStatus = false
		json.NewEncoder(w).Encode(follow)

	}

	if private == false {
		_, err = db.DB.Query("INSERT INTO follower(user_id,follower_id) VALUES($1,$2)", x.MyId, x.Following)
		if err != nil {
			_, err = db.DB.Query("DELETE FROM follower WHERE follower_id=$1", x.Following)
			if err != nil {
				panic(err)
			}
			var follow models.FollowStatus
			follow.FollowStatus = false
			json.NewEncoder(w).Encode(follow)
			return

		}
		var follow models.FollowStatus
		follow.FollowStatus = true
		json.NewEncoder(w).Encode(follow)
	}

}
func GetFollowers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method invalid", http.StatusMethodNotAllowed)
		return
	}
	var userId models.UserID
	err := json.NewDecoder(r.Body).Decode(&userId)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusMethodNotAllowed)
		return
	}

	var follower models.Follows
	var followers []models.Follows

	row, err := db.DB.Query("SELECT user_id FROM follower WHERE follower_id=$1 AND accepted=$2", userId.UserId, true)
	if err != nil {
		panic(err)
	}

	for row.Next() {
		err = row.Scan(&follower.UserID)
		if err != nil {
			panic(err)
		}

		err = db.DB.QueryRow("SELECT name,user_name,display_pic FROM users WHERE user_id=$1", follower.UserID).Scan(&follower.Name, &follower.UserName, &follower.ProfilePic)
		if err != nil {
			panic(err)
		}
		follower.ProfilePic = "http://localhost:3000/getProfilePic/" + follower.ProfilePic

		//to check following back status
		var id int64
		err = db.DB.QueryRow("SELECT user_id FROM follower WHERE follower_id=$1 AND accepted=$2", follower.UserID, true).Scan(&id)
		if err != nil {
			follower.FollowingBackStatus = false
		}

		if id != userId.UserId {
			follower.FollowingBackStatus = false
		} else {
			follower.FollowingBackStatus = true
		}

		followers = append(followers, follower)
	}

	json.NewEncoder(w).Encode(followers)
}
func PendingFollowRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var userId models.UserID
	json.NewDecoder(r.Body).Decode(&userId)

	if userId.UserId == 0 {
		http.Error(w, "Missing or invalid userId", http.StatusNotAcceptable)
		return
	}

	row, err := db.DB.Query("SELECT user_id,created_at,accepted FROM follower WHERE follower_id=$1 AND accepted=$2", userId.UserId, false)
	if err != nil {
		panic(err)
	}
	var followRequest []models.FollowRequest
	for row.Next() {
		var followrequest models.FollowRequest
		err = row.Scan(&followrequest.UserID, &followrequest.CreatedOn, &followrequest.Accepted)
		if err != nil {
			panic(err)
		}

		err = db.DB.QueryRow("SELECT user_name,display_pic FROM users WHERE user_id=$1", followrequest.UserID).Scan(&followrequest.UserName, &followrequest.ProfilePic)
		if err != nil {
			panic(err)
		}
		followrequest.ProfilePic = "http://localhost:3000/getProfilePhoto/" + followrequest.ProfilePic
		followRequest = append(followRequest, followrequest)

	}
	json.NewEncoder(w).Encode(followRequest)
}
func RespondingFollowRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}

	var accepted models.FollowAcceptance
	err := json.NewDecoder(r.Body).Decode(&accepted)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusNotAcceptable)
		return
	}

	//validate ids in db follower
	var user_id, follwer_id int64
	err = db.DB.QueryRow("SELECT user_id,follower_id FROM follower WHERE follower_id=$1 AND accepted=$2", accepted.AcceptorUserID, false).Scan(&user_id, &follwer_id)
	if err != nil {
		http.Error(w, "Request doesn't exist", http.StatusInternalServerError)
		return
	}

	if accepted.AcceptStatus {
		_, err = db.DB.Query("UPDATE follower SET accepted=$1 WHERE user_id=$2 AND follower_id=$3", true, accepted.RequestorId, accepted.AcceptorUserID)
		if err != nil {
			http.Error(w, "Couldn't update request", http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, "Accepted follow request")
	} else {
		_, err = db.DB.Query("DELETE FROM follower WHERE user_id=$1 AND follower_id=$2 AND accepted=$3", accepted.RequestorId, accepted.AcceptorUserID, false)
		if err != nil {
			http.Error(w, "Couldn't delete pending follow request", http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, "Deleted follow request")
	}
}
func RemoveFollowers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var follower models.DeleteFollower
	err := json.NewDecoder(r.Body).Decode(&follower)
	if err != nil {
		http.Error(w, "Error decoding the request body", http.StatusBadRequest)
		return
	}

	if follower.FollowerUserId == 0 && follower.MyuserId == 0 {
		http.Error(w, "Missing or invalid Ids", http.StatusInternalServerError)
		return
	}

	_, err = db.DB.Query("DELETE FROM follower WHERE user_id=$1 AND follower_id=$2 AND accepted=$3", follower.FollowerUserId, follower.MyuserId, true)
	if err != nil {
		http.Error(w, "Error removing the follower", http.StatusInternalServerError)
		return
	}
	fmt.Fprintln(w, "Removed follower successfully")

}
func GetFollowing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method invalid", http.StatusMethodNotAllowed)
		return
	}
	var userId models.UserID
	err := json.NewDecoder(r.Body).Decode(&userId)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusMethodNotAllowed)
		return
	}

	row, err := db.DB.Query("SELECT follower_id FROM follower WHERE user_id=$1 AND accepted=$2", userId.UserId, true)
	if err != nil {
		panic(err)
	}
	var following []models.Follows
	for row.Next() {
		var follow models.Follows
		err = row.Scan(&follow.UserID)
		if err != nil {
			panic(err)
		}
		err = db.DB.QueryRow("SELECT name,user_name,display_pic FROM users WHERE user_id=$1", follow.UserID).Scan(&follow.Name, &follow.UserName, &follow.ProfilePic)
		if err != nil {
			panic(err)
		}
		follow.ProfilePic = "http://localhost:3000/getProfilePic/" + follow.ProfilePic
		follow.FollowingBackStatus = true
		following = append(following, follow)
	}
	json.NewEncoder(w).Encode(following)
}
func UpdateBio(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var updateProfile models.ProfileUpdate
	err := json.NewDecoder(r.Body).Decode(&updateProfile)
	if err != nil {
		http.Error(w, "Error decoding request", http.StatusNoContent)
		return
	}

	if updateProfile.UserID <= 0 {
		http.Error(w, "User ID not accepted or missing field", http.StatusNotAcceptable)
		return
	}

	if len(updateProfile.Bio) > 150 {
		http.Error(w, "Bio exceeds the character limit (150)", http.StatusNotAcceptable)
		return
	}

	// user name validation

	match, _ := regexp.MatchString("^[a-zA-Z0-9][a-zA-Z0-9_]*$", updateProfile.UserName)
	if !match {
		fmt.Fprintln(w, "User name should start with alphabet and can have combination minimum 8 characters of numbers and only underscore(_)")
		return
	}

	if len(updateProfile.UserName) < 7 || len(updateProfile.UserName) > 20 {
		http.Error(w, "Username should be of length(7,20)", http.StatusMethodNotAllowed)
		return
	}

	//validate name
	if len(updateProfile.Name) > 20 {
		http.Error(w, "Name should be less than 20 characters", http.StatusMethodNotAllowed)
		return
	}

	_, err = db.DB.Query("UPDATE users SET bio =$1,name=$2,user_name=$3 WHERE user_id=$4", updateProfile.Bio, updateProfile.Name, updateProfile.UserName, updateProfile.UserID)
	if err != nil {
		panic(err)
	}

	fmt.Fprint(w, "Update successful")
}
func UpdateProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var userId models.UserID
	err := json.NewDecoder(r.Body).Decode(&userId)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusMethodNotAllowed)
		return
	}

	var profile models.Profile
	var partialURL string

	//get info from users table
	getProfile := `SELECT user_name,display_pic,bio,private FROM users WHERE user_id=$1`
	err = db.DB.QueryRow(getProfile, userId.UserId).Scan(&profile.UserName, &partialURL, &profile.Bio, &profile.PrivateAccount)
	if err != nil {
		panic(err)
	}

	profile.UserID = userId.UserId

	profile.ProfilePic = "http://localhost:3000/getProfilePic/" + partialURL

	//get count of total post of user
	getPostCount := `SELECT COUNT(post_id) FROM posts WHERE user_id=$1`
	err = db.DB.QueryRow(getPostCount, userId.UserId).Scan(&profile.PostCount)
	if err != nil {
		panic(err)
	}

	//get count of followers
	getFollowerCount := `SELECT COUNT(user_id) FROM follower WHERE follower_id=$1`
	err = db.DB.QueryRow(getFollowerCount, userId.UserId).Scan(&profile.FollowerCount)
	if err != nil {
		panic(err)
	}

	//get following count
	getFollowingCount := `SELECT COUNT(follower_id) FROM follower WHERE user_id=$1`
	err = db.DB.QueryRow(getFollowingCount, userId.UserId).Scan(&profile.FollowingCount)
	if err != nil {
		panic(err)
	}

	json.NewEncoder(w).Encode(profile)
}
func SavePosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var post models.LikePost //reusing struct with user_id and post_id fields
	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusMethodNotAllowed)
		return
	}

	if post.PostId == 0 || post.UserID == 0 {
		http.Error(w, "Invalid post or userd ID", http.StatusInternalServerError)
		return
	}

	err = db.DB.QueryRow("SELECT post_id FROM posts WHERE post_id=$1", post.PostId).Scan(&post.PostId)
	if err != nil {
		http.Error(w, "Invalid post id/doesnt exist in db posts", http.StatusNotAcceptable)
		return
	}

	var postId, userId int64
	var savedStatus models.SavedStatus
	err = db.DB.QueryRow("SELECT post_id,user_id FROM savedposts WHERE post_id=$1", post.PostId).Scan(&postId, &userId)
	if err != nil {
		//insert into savedposts  table

		_, err = db.DB.Query("INSERT INTO savedposts(post_id,user_id) VALUES($1,$2)", post.PostId, post.UserID)
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(w, "Saved successfully")
		savedStatus.SavedStatus = true
		json.NewEncoder(w).Encode(savedStatus)
		return

	}

	if postId == post.PostId && userId == post.UserID {
		_, err = db.DB.Query("DELETE FROM savedposts WHERE post_id=$1", postId)
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(w, "Removed from saved successfully")
		savedStatus.SavedStatus = false
		json.NewEncoder(w).Encode(savedStatus)
		return
	}

}
func SavedPosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var userId models.UserID
	err := json.NewDecoder(r.Body).Decode(&userId)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusMethodNotAllowed)
		return
	}

	if userId.UserId == 0 {
		fmt.Fprintln(w, "Invalid User ID")
		return
	}

	row, err := db.DB.Query("SELECT post_id FROM savedposts WHERE user_id=$1", userId.UserId)
	if err != nil {
		panic(err)
	}

	var finalpostid []models.SavedPosts
	for row.Next() {
		var postid models.SavedPosts
		var posturl string
		err = row.Scan(&postid.PostId)
		if err != nil {
			panic(err)
		}
		err = db.DB.QueryRow("SELECT post_path FROM posts WHERE post_id=$1", postid.PostId).Scan(&posturl)
		ext := strings.ToLower(filepath.Ext(posturl))

		postid.ContentType = models.GetExtension(ext)
		postid.PostURL = "http://localhost:3000/download/" + posturl
		finalpostid = append(finalpostid, postid)
	}

	json.NewEncoder(w).Encode(finalpostid)

}
func DeleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var loginCred models.LoginCred
	err := json.NewDecoder(r.Body).Decode(&loginCred)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusPartialContent)
		return
	}

	if loginCred.Password == "" && loginCred.UserName == "" {
		http.Error(w, "Invalid username or Password", http.StatusPartialContent)
		return
	}

	var passwordHash string
	err = db.DB.QueryRow("SELECT password FROM users WHERE user_name=$1", loginCred.UserName).Scan(&passwordHash)
	if err != nil {
		panic(err)
	}
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(loginCred.Password))
	if err == nil {
		_, err = db.DB.Query("DELETE FROM users WHERE user_name=$1", loginCred.UserName)
		if err != nil {
			http.Error(w, "Error occured while deleting account", http.StatusInternalServerError)
			return
		}
	}
	if err != nil {
		fmt.Fprintln(w, "Invalid password")
		return
	}

}
func RemoveSavedPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var remove models.LikePost //reusing struct
	err := json.NewDecoder(r.Body).Decode(&remove)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	if remove.PostId <= 0 || remove.UserID <= 0 {
		http.Error(w, "Missing field or invalid ids", http.StatusInternalServerError)
		return
	}

	err = db.DB.QueryRow("SELECT user_id,post_id FROM savedposts WHERE user_id=$1 AND post_id=$2", remove.UserID, remove.PostId).Scan(&remove.UserID, &remove.PostId)
	if err != nil {
		http.Error(w, "Invalid user_id", http.StatusInternalServerError)
		return
	}

	_, err = db.DB.Query("DELETE FROM savedposts WHERE user_id=$1 AND post_id=$2", remove.UserID, remove.PostId)
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(w, "Removed post from saved posts")
}
