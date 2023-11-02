package handlers

import (
	"backend/db"
	"backend/models"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

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

	//check for missing fields
	if userdata.Private == nil {
		http.Error(w, "Invalid or missing privateAccount field", http.StatusMethodNotAllowed)
		return
	}
	if userdata.UserName == "" {
		http.Error(w, "Missing userName field", http.StatusMethodNotAllowed)
		return
	}
	if userdata.Password == "" {
		http.Error(w, "Missing password field", http.StatusMethodNotAllowed)
		return
	}
	if userdata.Email == "" {
		http.Error(w, "Missing email field", http.StatusMethodNotAllowed)
		return
	}
	if userdata.PhoneNumber == "" {
		http.Error(w, "Missing phone number field", http.StatusMethodNotAllowed)
		return
	}
	if userdata.UserName == "" {
		http.Error(w, "Missing userName field", http.StatusMethodNotAllowed)
		return
	}
	if userdata.DOB == "" {
		http.Error(w, "Missing DOB field", http.StatusMethodNotAllowed)
		return
	}
	if userdata.Bio == nil {
		http.Error(w, "Missing bio field", http.StatusMethodNotAllowed)
		return
	}
	if userdata.Name == "" {
		http.Error(w, "Missing name field", http.StatusMethodNotAllowed)
		return
	}

	// user name validation

	match, _ := regexp.MatchString("^[a-zA-Z0-9][a-zA-Z0-9_]*$", userdata.UserName)
	if !match {
		fmt.Fprintln(w, "User name should start with alphabet and can have combination minimum 8 characters of numbers and only underscore(_)")
		return
	}

	if len(userdata.UserName) < 7 || len(userdata.UserName) > 20 {
		http.Error(w, "Username should be of length(7,20)", http.StatusMethodNotAllowed)
		return
	}

	if len(userdata.Name) > 20 {
		http.Error(w, "Name should be less than 20 character", http.StatusMethodNotAllowed)
		return
	}

	// user password validation
	if len(userdata.Password) == 0 {
		http.Error(w, "Missing password field", http.StatusMethodNotAllowed)
		return
	}

	match, _ = regexp.MatchString("[0-9]+?", userdata.Password)
	if !match {
		fmt.Fprintln(w, "Password must contain atleast one number")
		return
	}
	match, _ = regexp.MatchString("[A-Z]+?", userdata.Password)
	if !match {
		fmt.Fprintln(w, "Password must contain atleast upper case letter")
		return
	}
	match, _ = regexp.MatchString("[a-z]+?", userdata.Password)
	if !match {
		fmt.Fprintln(w, "Password must contain atleast lower case letter")
		return
	}
	match, _ = regexp.MatchString("[!@#$%^&*_]+?", userdata.Password)
	if !match {
		fmt.Fprintln(w, "Password must contain atleast special character")
		return
	}
	match, _ = regexp.MatchString(".{8,30}", userdata.Password)
	if !match {
		fmt.Fprintln(w, "Password length must be atleast 8 character long")
		return
	}

	//phone number validation
	match, _ = regexp.MatchString("^[+]{1}[0-9]{0,3}\\s?[0-9]{10}$", userdata.PhoneNumber)
	if !match {
		fmt.Fprintln(w, "Please enter valid phone number")
		return
	}

	//validate email using net/mail
	emailregex := regexp.MustCompile("^[A-Za-za0-9.!#$%&'*+\\/=?^_`{|}~-]+@[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
	match = emailregex.MatchString(userdata.Email)
	if !match {
		fmt.Fprintln(w, "Please enter valid email")
		return
	}
	if len(userdata.Email) < 3 && len(userdata.Email) > 254 {
		http.Error(w, "Invalid email", http.StatusMethodNotAllowed)
		return
	}

	i := strings.Index(userdata.Email, "@")
	host := userdata.Email[i+1:]

	_, err = net.LookupMX(host)
	if err != nil {
		http.Error(w, "Invalid email(host not found)", http.StatusMethodNotAllowed)
		return
	}
	//validate date
	layout := "2006-01-02"
	bdate, err := time.Parse(layout, userdata.DOB)
	if err != nil {
		fmt.Fprintln(w, "Enter a valid date format")
		return
	}
	cdate := time.Now()

	age := cdate.Sub(bdate)
	if age.Hours() < 113958 {
		fmt.Fprintln(w, "Enter proper date of birth,You ahould be minimum of 13 years old to create an account")
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

const MB = 1 << 20

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

func DownloadPosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	url := fmt.Sprint(r.URL)

	_, file := path.Split(url)

	imagePath := "./posts/" + file

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

func PostMedia(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var postInfo models.InsertPost
	err := json.NewDecoder(r.Body).Decode(&postInfo)
	if err != nil {
		fmt.Fprintln(w, "Check input data field formats")
		return
	}

	//check for missing fields
	if postInfo.TurnOffComments == nil || postInfo.HideLikeCount == nil || postInfo.Location == nil || postInfo.UserID == nil || postInfo.PostCaption == nil {
		http.Error(w, "Missing field/fields in the request", http.StatusMethodNotAllowed)
		return
	}

	//validate input user id

	match, _ := regexp.MatchString("^.*[0-9]$", strconv.Itoa(int(*postInfo.UserID)))
	if !match {
		fmt.Fprintln(w, "check input post id format")
		return
	}

	if len(postInfo.HashtagIds) > 30 {
		http.Error(w, "You can use only 30 hashtags in the caption", http.StatusInternalServerError)
		return
	}
	if len(postInfo.TaggedIds) > 20 {
		http.Error(w, "Only 20 users can be tagged", http.StatusInternalServerError)
		return
	}

	var idexists bool
	err = db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE user_id=$1)", postInfo.UserID).Scan(&idexists)
	if err != nil {
		http.Error(w, "Invalid user-id", http.StatusInternalServerError)
		return
	}

	if !idexists {
		http.Error(w, "No user exists with this user-id", http.StatusInternalServerError)
		return
	}

	//check for existance of tagged ids

	for _, id := range postInfo.TaggedIds {
		err = db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE user_id=$1)", id).Scan(&idexists)
		if err != nil {
			http.Error(w, "Invalid user-id", http.StatusBadRequest)
			return
		}
		if !idexists {
			http.Error(w, "No user exists with this tagged id", http.StatusBadRequest)
			fmt.Fprint(w, id)
			return
		}
	}

	//check for existance of hash ids
	for _, id := range postInfo.HashtagIds {
		err = db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM hashtags WHERE hash_id=$1)", id).Scan(&idexists)
		if err != nil {
			http.Error(w, "Invalid hash-id", http.StatusInternalServerError)
			return
		}
		if !idexists {
			http.Error(w, "Invalid hash-id", http.StatusInternalServerError)
			return
		}
	}

	// //validate input location format
	if *postInfo.Location != "" {
		pointRegex := regexp.MustCompile(`^[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)$`)
		if !pointRegex.MatchString(*postInfo.Location) {
			fmt.Fprintln(w, "check input location format")
			return
		}
	} else {
		*postInfo.Location = "0,0" //stuff user location when there is access
	}

	//check for max length of post caption 150 chars
	if len(*postInfo.PostCaption) > 2200 {
		http.Error(w, "Max allowed length of post caption is 2200 character", http.StatusNotAcceptable)
		return
	}

	var postId models.PostId
	insertPostInfo := `INSERT INTO posts(user_id,poat_caption,location,hide_like,hide_comments) VALUES($1,$2,$3,$4,$5) RETURNING post_id`
	err = db.DB.QueryRow(insertPostInfo, postInfo.UserID, postInfo.PostCaption, postInfo.Location, postInfo.HideLikeCount, postInfo.TurnOffComments).Scan(&postId.PostId)
	if err != nil {
		panic(err)
	}

	//update tags
	for _, tagid := range postInfo.TaggedIds {
		_, err = db.DB.Query("INSERT INTO tagged_users(post_id,tagged_ids) VALUES($1,$2)", postId.PostId, tagid)
		if err != nil {
			db.DB.Query("DELETE FROM posts WHERE post_id=$1", postId.PostId)
			http.Error(w, "Error inserting tagged users", http.StatusInternalServerError)
			return
		}

	}

	//check for hashtags

	for _, hashid := range postInfo.HashtagIds {
		_, err = db.DB.Query("INSERT INTO mentions(hash_id,post_id) VALUES($1,$2)", hashid, postId.PostId)
		if err != nil {
			fmt.Println(err)
			db.DB.Query("DELETE FROM tagged_users WHERE post_id=$1", postId.PostId)
			http.Error(w, "Error inserting mentions", http.StatusInternalServerError)
			return
		}
	}

	json.NewEncoder(w).Encode(postId)

	fmt.Fprintf(w, "Posts uploaded successfully.")

}

func PostMediaPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096*MB)
	err := r.ParseMultipartForm(4096 * MB)
	if err != nil {
		http.Error(w, "Error parsing multipart form data", http.StatusInternalServerError)
		return
	}
	jsonData := r.FormValue("postId")

	var postId models.PostId

	err = json.Unmarshal([]byte(jsonData), &postId)
	if err != nil {

		http.Error(w, "Error unmarshalling JSON data,Enter correct postID", http.StatusInternalServerError)
		return
	}

	var tempid int64
	err = db.DB.QueryRow("SELECT post_id FROM posts WHERE post_id=$1", postId.PostId).Scan(&tempid)
	if err != nil {
		http.Error(w, "Invalid post_id", http.StatusInternalServerError)
		return
	}

	if tempid != postId.PostId {
		http.Error(w, "Invalid post_id", http.StatusInternalServerError)
		return
	}

	var postPath []string
	fileHeaders := r.MultipartForm.File
	if len(fileHeaders) == 0 {
		http.Error(w, "No files attached", http.StatusInternalServerError)
		return
	}

	for _, fileHeaders := range fileHeaders {
		for _, fileHeader := range fileHeaders {
			if len(fileHeaders) > 10 {
				http.Error(w, "Only 10 files allowed", http.StatusInternalServerError)
				return
			}
			file, err := fileHeader.Open()
			if err != nil {
				http.Error(w, "Unable to open the file", http.StatusInternalServerError)
				return
			}
			defer file.Close()

			//check for file allowed file format
			match, _ := regexp.MatchString("^.*\\.(jpg|JPG|png|PNG|JPEG|jpeg|bmp|BMP|MP4|mp4|mov|MOV|GIF|gif)$", fileHeader.Filename)
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

			// image, _, err := image.DecodeConfig(file)
			// if err != nil {
			// 	http.Error(w, "Cannot read the image configs", http.StatusInternalServerError)
			// 	return
			// }

			// if image.Height < 155 && image.Width < 155 {
			// 	http.Error(w, "Image resolution too low", http.StatusInternalServerError)
			// 	return
			// }

			// fmt.Fprintln(w, fileHeader.Filename, ":", image.Width, "x", image.Height)

			if match, _ := regexp.MatchString("^.*\\.(MP4|mp4|mov|MOV|GIF|gif)$", fileHeader.Filename); match {
				//check for the file size
				if size := fileHeader.Size; size > 3584*MB {
					http.Error(w, "File size exceeds 3.6GB", http.StatusInternalServerError)
					return
				}

			}

			//Create a new file on the server
			//get cleaned file name
			s := regexp.MustCompile(`\s+`).ReplaceAllString(fileHeader.Filename, "")
			time := fmt.Sprintf("%v", time.Now())
			s = regexp.MustCompile(`\s+`).ReplaceAllString(time, "") + s

			dst, err := os.Create(filepath.Join("./posts", s))
			if err != nil {
				http.Error(w, "Unable to create a file", http.StatusInternalServerError)
				return
			}
			defer dst.Close()

			_, err = io.Copy(dst, file)
			if err != nil {
				http.Error(w, "Unable to write file", http.StatusInternalServerError)
				return
			}

			postPath = append(postPath, filepath.Join("./posts", s))

		}

	}
	requestBodyPostPath := fmt.Sprintf("%s", strings.Join(postPath, ","))
	insertPostPath := `UPDATE posts SET post_path=$1,complete_post=$2 WHERE post_id=$3`
	_, err = db.DB.Query(insertPostPath, requestBodyPostPath, true, postId.PostId)
	if err != nil {
		panic(err)
		// http.Error(w, "Error inserting to DB", http.StatusInternalServerError)

	}

	json.NewEncoder(w).Encode("Media uploaded successfully")
}

func AllPosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var userPosts []models.UsersPost

	var userId models.UserID
	// userId.UserId = 1
	err := json.NewDecoder(r.Body).Decode(&userId)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusMethodNotAllowed)
		return
	}
	if userId.UserId == 0 {
		fmt.Fprintln(w, "Invalid user id or missing field")
		return
	}

	getPosts := `SELECT post_id,post_path,poat_caption,location,hide_like,hide_comments,posted_on FROM posts WHERE user_id=$1 ORDER BY posted_on DESC`
	row, err := db.DB.Query(getPosts, userId.UserId)
	if err != nil {
		panic(err)
	}
	for row.Next() {
		//to get username
		var userPost models.UsersPost
		getUserName := `SELECT user_name,display_pic FROM users WHERE user_id=$1`
		var url string
		err = db.DB.QueryRow(getUserName, userId.UserId).Scan(&userPost.UserName, &url)

		userPost.UserProfilePicURL = "http://localhost:3000/getProfilePic/" + url
		if err != nil {
			http.Error(w, "Unable to get username", http.StatusInternalServerError)
			return
		}
		var postURLstr string
		err = row.Scan(&userPost.PostId, &postURLstr, &userPost.PostCaption, &userPost.AttachedLocation, &userPost.HideLikeCount, &userPost.HideLikeCount, &userPost.PostedOn)
		if err != nil {
			panic(err)
		}

		//get like status of present user
		err = db.DB.QueryRow("SELECT EXISTS(SELECT user_name FROM likes WHERE post_id=$1 AND user_name=$2)", userPost.PostId, userPost.UserName).Scan(&userPost.LikeStatus)
		if err != nil {
			panic(err)
		}

		//get count of likes
		err = db.DB.QueryRow("SELECT COUNT(user_name) FROM likes WHERE post_id=$1", userPost.PostId).Scan(&userPost.Likes)
		if err != nil {
			panic(err)
		}
		postURL := strings.Split(postURLstr, ",")
		for _, url := range postURL {
			url = "http://localhost:3000/download/" + url
			userPost.PostURL = append(userPost.PostURL, url)

		}

		err = db.DB.QueryRow("SELECT user_id,post_id FROM savedposts WHERE user_id=$1.post_id=$2", userPost.UserID, userPost.PostId).Scan(&userPost.UserID, &userPost.PostId)
		if err != nil {
			userPost.SavedStatus = false
		} else {
			userPost.SavedStatus = true
		}

		userPost.UserID = userId.UserId
		userPosts = append(userPosts, userPost)
	}
	json.NewEncoder(w).Encode(userPosts)

}

func LikePosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var requestBody models.LikePost
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusMethodNotAllowed)
		return
	}
	//validate for proper userId and PostId
	if requestBody.PostId == 0 || requestBody.UserID == 0 {
		fmt.Fprintln(w, "Invalid userId or PostId/missing fields")
		return
	}

	getUserName := `SELECT user_name FROM users WHERE user_id=$1`
	var userName string
	err = db.DB.QueryRow(getUserName, requestBody.UserID).Scan(&userName)
	if err != nil {
		panic(err)
	}

	insertLike := `INSERT INTO likes(post_id,user_name) VALUES($1,$2)`
	_, err = db.DB.Query(insertLike, requestBody.PostId, userName)
	if err != nil {

		_, err := db.DB.Query("DELETE FROM likes WHERE user_name=$1", userName)
		if err != nil {
			panic(err)
		}

	}

	getTotalLikes := `SELECT COUNT(user_name) FROM likes WHERE post_id=$1`
	var likes models.TotalLikes
	err = db.DB.QueryRow(getTotalLikes, requestBody.PostId).Scan(&likes.TotalLikes)
	if err != nil {
		panic(err)
	}
	json.NewEncoder(w).Encode(likes)
}

func CommentPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var requestBody models.CommentBody
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusNotAcceptable)
		return
	}
	//validate for proper userId and PostId
	if requestBody.PostId == 0 || requestBody.UserID == 0 {
		fmt.Fprintln(w, "Invalid userId or PostId or missing fields")
		return
	}
	if requestBody.CommentBody == "" {
		http.Error(w, "CommentBody cannot be empty or missing field", http.StatusNotAcceptable)
		return
	}

	if len(requestBody.CommentBody) > 2500 {
		http.Error(w, "Comment body should not exceed 2500 characters", http.StatusNotAcceptable)
		return
	}

	insertComment := `INSERT INTO comments(commentoruser_id,post_id,comment_body) VALUES($1,$2,$3) RETURNING comment_id`
	var returnedCommentId models.ReturnedCommentId

	err = db.DB.QueryRow(insertComment, requestBody.UserID, requestBody.PostId, requestBody.CommentBody).Scan(&returnedCommentId.ReturnedCommentId)
	if err != nil {
		http.Error(w, "Invalid post id", http.StatusBadRequest)
	}
	json.NewEncoder(w).Encode(returnedCommentId)

}

func AllComments(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var postId models.PostId
	err := json.NewDecoder(r.Body).Decode(&postId)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusMethodNotAllowed)
		return
	}
	if postId.PostId == 0 {
		fmt.Fprintln(w, "Invalid post id")
		return
	}

	err = db.DB.QueryRow("SELECT post_id FROM posts WHERE post_id=$1", postId.PostId).Scan(&postId.PostId)
	if err != nil {
		http.Error(w, "Invalid post id", http.StatusInternalServerError)
		return
	}

	var comments []models.CommentsOfPost
	var comment models.CommentsOfPost
	row, err := db.DB.Query("SELECT commentoruser_id,comment_id,comment_body,commented_on FROM comments WHERE post_id=$1 ORDER BY commented_on DESC", postId.PostId)
	if err != nil {
		panic(err)
	}
	for row.Next() {
		var commentorUSerID int64
		err = row.Scan(&commentorUSerID, &comment.CommentId, &comment.CommentBody, &comment.CommentedOn)
		if err != nil {
			panic(err)
		}

		var dpURL string
		err = db.DB.QueryRow("SELECT user_name,display_pic FROM users WHERE user_id=$1", commentorUSerID).Scan(&comment.CommentorUserName, &dpURL)
		if err != nil {
			panic(err)
		}
		comment.CommentorDisplayPic = "http://localhost:3000/getProfilePic/" + dpURL
		comment.PostId = postId.PostId
		comments = append(comments, comment)

	}
	json.NewEncoder(w).Encode(comments)

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

func GetPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	//:var id int64
	idstr := fmt.Sprint(r.URL)

	_, idstr = path.Split(idstr)

	postId, err := strconv.Atoi(idstr)
	if err != nil {
		http.Error(w, "Bad post id", http.StatusMethodNotAllowed)
		return
	}

	err = db.DB.QueryRow("SELECT post_id FROM posts WHERE post_id=$1 AND complete_post=$2", postId, true).Scan(&postId)
	if err != nil {
		http.Error(w, "Invalid postId or does not exist", http.StatusInternalServerError)
		return
	}
	var post models.UsersPost

	post.PostId = int64(postId)

	var postURL string
	query := `SELECT user_id,post_path,poat_caption,location,hide_like,hide_comments,posted_on FROM posts WHERE post_id=$1 AND complete_post=$2`
	err = db.DB.QueryRow(query, postId, true).Scan(&post.UserID, &postURL, &post.PostCaption, &post.AttachedLocation, &post.HideLikeCount, &post.TurnOffComments, &post.PostedOn)
	if err != nil {
		// http.Error(w, "Error fetching data from db posts", http.StatusInternalServerError)
		// return
		panic(err)
	}

	filetype := strings.Split(postURL, ".")
	post.FileType = models.GetExtension("." + filetype[len(filetype)-1])

	postURL = "http://localhost:3000/download/" + postURL
	post.PostURL = append(post.PostURL, postURL)

	var URL string
	err = db.DB.QueryRow("SELECT user_name,display_pic FROM users WHERE user_id=$1", post.UserID).Scan(&post.UserName, &URL)
	if err != nil {
		http.Error(w, "Error retriving data from db users", http.StatusInternalServerError)
		return
	}
	post.UserProfilePicURL = "http://localhost:3000/getProfilePic/" + URL

	err = db.DB.QueryRow("SELECT COUNT(user_name) FROM likes WHERE post_id=$1", postId).Scan(&post.Likes)
	if err != nil {
		http.Error(w, "Error retriving likes count", http.StatusInternalServerError)
		return
	}

	//pending : update like status

	err = json.NewEncoder(w).Encode(post)
	if err != nil {
		// http.Error(w,"Error encoding response",http.StatusInternalServerError)
		fmt.Fprintln(w, "Error encoding response")
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

func TurnOffComments(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var commentoff models.LikePost //reusing struct fields
	err := json.NewDecoder(r.Body).Decode(&commentoff)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	if commentoff.PostId <= 0 || commentoff.UserID <= 0 {
		fmt.Fprintln(w, "Invalid ids or missing field")
		return
	}

	err = db.DB.QueryRow("SELECT user_id,post_id FROM posts WHERE user_id=$1 AND post_id=$2", commentoff.UserID, commentoff.PostId).Scan(&commentoff.UserID, &commentoff.PostId)
	if err != nil {
		panic(err)
	}

	_, err = db.DB.Query("UPDATE posts SET hide_comments=$1 WHERE user_id=$2", true, commentoff.UserID)
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(w, "Comments turned off")

}

func TurnONComments(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var commentoff models.LikePost //reusing struct fields
	err := json.NewDecoder(r.Body).Decode(&commentoff)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	if commentoff.PostId <= 0 || commentoff.UserID <= 0 {
		fmt.Fprintln(w, "Invalid ids or missing field")
		return
	}

	err = db.DB.QueryRow("SELECT user_id,post_id FROM posts WHERE user_id=$1 AND post_id=$2", commentoff.UserID, commentoff.PostId).Scan(&commentoff.UserID, &commentoff.PostId)
	if err != nil {
		panic(err)
	}

	_, err = db.DB.Query("UPDATE posts SET hide_comments=$1 WHERE user_id=$2", false, commentoff.UserID)
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(w, "Comments turned on")

}

func HideLikeCount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var commentoff models.LikePost //reusing struct fields
	err := json.NewDecoder(r.Body).Decode(&commentoff)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	if commentoff.PostId <= 0 || commentoff.UserID <= 0 {
		fmt.Fprintln(w, "Invalid ids or missing field")
		return
	}

	err = db.DB.QueryRow("SELECT user_id,post_id FROM posts WHERE user_id=$1 AND post_id=$2", commentoff.UserID, commentoff.PostId).Scan(&commentoff.UserID, &commentoff.PostId)
	if err != nil {
		panic(err)
	}

	_, err = db.DB.Query("UPDATE posts SET hide_like=$1 WHERE user_id=$2", true, commentoff.UserID)
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(w, "updated hide_like=true")

}

func ShowLikeCount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var commentoff models.LikePost //reusing struct fields
	err := json.NewDecoder(r.Body).Decode(&commentoff)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	if commentoff.PostId <= 0 || commentoff.UserID <= 0 {
		fmt.Fprintln(w, "Invalid ids or missing field")
		return
	}

	err = db.DB.QueryRow("SELECT user_id,post_id FROM posts WHERE user_id=$1 AND post_id=$2", commentoff.UserID, commentoff.PostId).Scan(&commentoff.UserID, &commentoff.PostId)
	if err != nil {
		panic(err)
	}

	_, err = db.DB.Query("UPDATE posts SET hide_like=$1 WHERE user_id=$2", false, commentoff.UserID)
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(w, "updated hide_likes=false")

}

func DeleteComment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var deleteComment models.DeleteComment
	err := json.NewDecoder(r.Body).Decode(&deleteComment)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	if deleteComment.CommentId <= 0 || deleteComment.PostId <= 0 || deleteComment.UserID <= 0 {
		http.Error(w, "Missing fields or inavlid ids", http.StatusResetContent)
		return
	}

	err = db.DB.QueryRow("SELECT user_id,post_id FROM posts WHERE user_id=$1 AND post_id=$2", deleteComment.UserID, deleteComment.PostId).Scan(&deleteComment.UserID, &deleteComment.PostId)
	if err != nil {
		http.Error(w, "Invalid Ids for operation", http.StatusInternalServerError)
		return
	}

	err = db.DB.QueryRow("SELECT post_id,comment_id FROM comments WHERE post_id=$1 AND comment_id=$2", deleteComment.PostId, deleteComment.CommentId).Scan(&deleteComment.PostId, &deleteComment.CommentId)
	if err != nil {
		http.Error(w, "Invalid Ids for operation", http.StatusInternalServerError)
		return
	}

	_, err = db.DB.Query("DELETE FROM comments WHERE post_id=$1 AND comment_id=$2", deleteComment.PostId, deleteComment.CommentId)
	if err != nil {
		http.Error(w, "error deleting comment", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "Comment deleted succefully")

}

func SearchAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var username models.UserName
	err := json.NewDecoder(r.Body).Decode(&username)
	if err != nil {
		http.Error(w, "error decoding request body", http.StatusBadRequest)
		return
	}

	if username.UserName == "" {
		http.Error(w, "Invalid user name or missing field", http.StatusPartialContent)
		return
	}

	str := regexp.MustCompile(`[a-zA-Z]*`)
	name := str.FindAllString(username.UserName, 1)

	num := regexp.MustCompile(`\d+`)
	number := num.FindAllString(username.UserName, 1)

	var like string
	if len(number) == 0 {
		like = "%" + name[0] + "%"
	}
	if len(name) == 0 {
		like = "%" + number[0] + "%"
	}
	if len(name) != 0 && len(number) != 0 {
		like = "%" + name[0] + "%" + number[0] + "%"
	}
	row, err := db.DB.Query("SELECT user_id,user_name,name,display_pic FROM users WHERE user_name ILIKE $1", like)
	if err != nil {
		panic(err)
	}

	var accounts []models.Accounts
	for row.Next() {
		var acc models.Accounts
		err = row.Scan(&acc.UserID, &acc.UserName, &acc.Name, &acc.ProfilePic)
		if err != nil {
			panic(err)
		}
		acc.ProfilePic = "http://localhost:3000/getProfilePic/" + acc.ProfilePic
		accounts = append(accounts, acc)

	}

	json.NewEncoder(w).Encode(accounts)
}

func SearchHashtag(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var hashtag models.HashtagSearch
	err := json.NewDecoder(r.Body).Decode(&hashtag)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusPartialContent)
		return
	}
	str := regexp.MustCompile(`[a-zA-Z_]*`)
	name := str.FindAllString(hashtag.Hashtag, 1)

	num := regexp.MustCompile(`\d+`)
	number := num.FindAllString(hashtag.Hashtag, 1)

	var like string
	if len(number) == 0 {
		like = name[0] + "%"
	}
	if len(name) == 0 {
		like = number[0] + "%"
	}
	if len(name) != 0 && len(number) != 0 {
		like = name[0] + "%" + number[0] + "%"
	}

	row, err := db.DB.Query("SELECT hash_id,hash_name FROM hashtags WHERE hash_name ILIKE $1", like)
	if err != nil {
		panic(err)
	}

	var results []models.HashtagSearchResult
	for row.Next() {
		var result models.HashtagSearchResult
		err = row.Scan(&result.HashId, &result.HashName)
		if err != nil {
			http.Error(w, "error reading hashtable", http.StatusInternalServerError)
			return
		}

		if result.HashId == 0 {
			fmt.Println("its empty")

		}

		err = db.DB.QueryRow("SELECT COUNT(post_id) FROM mentions WHERE hash_id=$1", result.HashId).Scan(&result.PostCount)
		if err != nil {
			http.Error(w, "Error getting count of posts of hash", http.StatusInternalServerError)
			return
		}

		results = append(results, result)

	}
	var newhashtag models.Newhashtag
	if len(results) == 0 {

		err = db.DB.QueryRow("INSERT INTO hashtags(hash_name) VALUES($1) RETURNING hash_id", hashtag.Hashtag).Scan(&newhashtag.NewHashId)
		if err != nil {
			panic(err)
			// http.Error(w, "Error creating new hash", http.StatusInternalServerError)
			// return
		}

		json.NewEncoder(w).Encode(newhashtag)

	}

	if len(results) != 0 {
		json.NewEncoder(w).Encode(results)
	}

}

func PostUploadStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not allowed", http.StatusMethodNotAllowed)
		return
	}
	var post_id models.PostId
	err := json.NewDecoder(r.Body).Decode(&post_id)
	if err != nil {
		panic(err)
	}
	var postUploadStatus models.SavedStatus
	err = db.DB.QueryRow("SELECT complete_post FROM posts WHERE post_id=$1", post_id.PostId).Scan(&postUploadStatus.SavedStatus)
	if err != nil {
		panic(err)
	}

	json.NewEncoder(w).Encode(postUploadStatus)
}
