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

		_, err := db.Query("DELETE FROM likes WHERE user_name=$1", userName)
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
