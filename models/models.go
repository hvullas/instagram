package models

type NewUser struct {
	UserName       string  `json:"user_name"`
	Password       string  `json:"password"`
	Name           string  `json:"name"`
	Email          string  `json:"email"`
	PhoneNumber    string  `json:"phone_number"`
	DOB            string  `json:"DOB"`
	Private        *bool   `json:"private_account"`
	Bio            *string `json:"bio"`
	DisplayPicture string  `json:"display_picture"`
}

type UserName struct {
	UserName string `json:"user_name"`
}

type GetProfilePicURL struct {
	PicURL string `json:"picURL"`
}

// struct to insert a post to db
type InsertPost struct {
	UserID          *int64   `json:"user_id"`
	PostPath        []string `json:"post_path"`
	PostCaption     *string  `json:"post_caption"`
	HashtagIds      []int64  `json:"hashtag_ids"`
	TaggedIds       []int64  `json:"tagged_ids"`
	Location        *string  `json:"location"`
	HideLikeCount   *bool    `json:"hide_like_count"`
	TurnOffComments *bool    `json:"turnoff_comments"`
}

// returned postid by postMedia api
type PostId struct {
	PostId int64 `json:"post_id"`
}
type UserID struct {
	UserId int64 `json:"user_id"`
}

// struct to get user posts and post by postId
type UsersPost struct {
	UserID            int64    `json:"user_iD"`
	UserName          string   `json:"user_name"`
	UserProfilePicURL string   `json:"user_profile_picUrl"`
	PostId            int64    `json:"post_id"`
	PostURL           []string `json:"postURL"`
	FileType          string   `json:"file_type"`
	AttachedLocation  string   `json:"attached_location"`
	LikeStatus        bool     `json:"like_status"`
	Likes             int64    `json:"likes"`
	PostCaption       string   `json:"caption"`
	HideLikeCount     bool     `json:"hide_like_count"`
	TurnOffComments   bool     `json:"turnoff_comments"`
	SavedStatus       bool     `json:"saved_post"`
	PostedOn          string   `json:"posted_on"`
}

// posting like to a post
type LikePost struct {
	PostId int64 `json:"post_id"`
	UserID int64 `json:"user_id"`
}

// to get count of likes on a post
type TotalLikes struct {
	TotalLikes int64 `json:"total_likes"`
}

// to post a comment
type CommentBody struct {
	PostId      int64  `json:"post_id"`
	UserID      int64  `json:"user_id"`
	CommentBody string `json:"comment_body"`
}

// comment id returned after succefull comment insertion
type ReturnedCommentId struct {
	ReturnedCommentId int64 `json:"returned_commentId"`
}

// to get the comments by post id
type CommentsOfPost struct {
	CommentId           int64  `json:"comment_id"`
	CommentorUserName   string `json:"commentor_user_name"`
	CommentorDisplayPic string `json:"commentor_display_pic"`
	PostId              int64  `json:"post_id"`
	CommentBody         string `json:"comment_body"`
	CommentedOn         string `json:"commented_on"`
}

// to delete a comment
type DeleteComment struct {
	UserID    int64 `json:"user_id"`
	PostId    int64 `json:"post_id"`
	CommentId int64 `json:"comment_id"`
}

// login
type LoginCred struct {
	UserName string `josn:"user_name"`
	Password string `josn:"password"`
}

// to follow another user
type Follow struct {
	MyId      int64 `json:"my_id"`
	Following int64 `json:"following_id"`
}

type FollowStatus struct {
	FollowStatus bool `json:"follow_status"`
}
type SavedStatus struct {
	SavedStatus bool `json:"saved_status"`
}

// to update bio of profile
type ProfileUpdate struct {
	UserID   int64  `json:"user_id"`
	Name     string `json:"name"`
	UserName string `json:"user_name"`
	Bio      string `json:"bio"`
}

// to give profile info response
type Profile struct {
	UserID         int64  `json:"user_id"`
	UserName       string `json:"user_name"`
	PrivateAccount bool   `json:"private_account"`
	PostCount      int64  `json:"post_count"`
	FollowerCount  int64  `json:"follower_count"`
	FollowingCount int64  `json:"following_count"`
	Bio            string `json:"bio"`
	ProfilePic     string `json:"profile_picURL"`
}

// to get all follower and following
type Follows struct {
	UserID              int64  `json:"user_id"`
	UserName            string `json:"user_name"`
	Name                string `json:"name"`
	ProfilePic          string `json:"profile_pic"`
	FollowingBackStatus bool   `json:"following_back_status"`
}

// to serve search results
type Accounts struct {
	UserID     int64  `json:"user_id"`
	UserName   string `json:"user_name"`
	Name       string `json:"name"`
	ProfilePic string `json:"profile_pic"`
}

// saved posts response
type SavedPosts struct {
	PostId      int64  `json:"post_id"`
	PostURL     string `json:"postURL"`
	ContentType string `json:"content_type"`
}

// to serve follow requests
type FollowRequest struct {
	UserID     int64  `json:"requestor_user_id"`
	UserName   string `json:"requestor_user_name"`
	ProfilePic string `json:"requestor_profile_pic"`
	CreatedOn  string `json:"request_created_on"`
	Accepted   bool   `json:"accepted"`
}
type FollowAcceptance struct {
	AcceptorUserID int64 `json:"acceptor_user_id"`
	RequestorId    int64 `json:"requestor_user_id"`
	AcceptStatus   bool  `json:"acceptance_status"`
}
type DeleteFollower struct {
	MyuserId       int64 `json:"my_user_id"`
	FollowerUserId int64 `json:"follower_user_id"`
}

type HashtagSearch struct {
	Hashtag string `json:"hashtag"`
}

type HashtagSearchResult struct {
	HashId    int64  `json:"hash_id"`
	HashName  string `json:"hash_name"`
	PostCount int64  `json:"total_posts"`
}
type Newhashtag struct {
	NewHashId int64 `json:"new_hash_tag_id"`
}
type StoryInfo struct {
	UserID    int64     `json:"user_id"`
	TaggedIds [][]int64 `json:"tagged_ids"`
}
type StoryMedia struct {
	StoryId int64 `json:"story_id"`
}

type ReturnedStoryId struct {
	ReturnedStoryId int64 `json:"returned_story_id"`
	PostAsStory     bool  `json:"post_as_story"`
}

type UploadStory struct {
	StoryId  int64 `json:"story_id"`
	Uploaded bool  `json:"uploaded"`
}

type GetStory struct {
	StoryId   int64   `json:"story_id"`
	StoryURL  string  `json:"storyurl"`
	PostedOn  string  `json:"posted_on"`
	Success   bool    `json:"upload_status"`
	TaggedIds []int64 `json:"tagged_userids"`
	FileType  string  `json:"file_type"`
}
type PostAsStory struct {
	UserID    int64   `json:"user_id"`
	TaggedIds []int64 `json:"tagged_ids"`
	StoryURL  string  `json:"storyURL"`
}

type ActiveStories struct {
	User_id        int64   `json:"user_id"`
	User_name      string  `json:"user_name"`
	Profile_picURL string  `json:"profile_pic_url"`
	Story_id       []int64 `json:"story_ids"`
	Seen_status    bool    `json:"story_seen_status"`
}

type UpdateStorySeenStatus struct {
	UserID  int64 `json:"user_id"`
	StoryId int64 `json:"story_id"`
}

// func to get the file extensions(used while serving files)
func GetExtension(extension string) string {
	switch extension {
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	case ".bmp":
		return "image/bmp"
	case ".mp4":
		return "video/mp4"
	case ".mov":
		return "video/quicktime"
	default:
		return ""
	}
}
