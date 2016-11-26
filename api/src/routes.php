<?php

/**
*	Get Table Schema
*/

$app->group('/api/db/schema', function () {

	/**
	 * Get Table Names
	 * url - /api/db/schema/table
	 * method - GET
	 * params - 
	 */
    $this->get('/table', function ($request, $response, $args) {
    	$dbhandler = $this->db;
		$stmt = $dbhandler->prepare('SHOW TABLES');
		$stmt->execute();
		$response->withJson($stmt->fetchAll(),  201, json_encode());
		return $response;


		/**
		$code = 1;
		$status = true;
		$data = $stmt->fetchAll();
		$message = array('code' => $code , 'status' => $status, 'data'=> $data);     	
		$response->withJson($message,  200)->withHeader('Content-Type', 'application/json');
		return $response;
		*/
        
    });

    /**
	 * Get The Schema OF Every Individual Table
	 * url - /api/db/schema/{table_name}
	 * method - GET
	 * params - 
	 */
    $this->get('/{tblName}', function ($request, $response, $args) {
    	$tblName = $request->getAttribute('tblName');
    	$dbhandler = $this->db;
		$stmt = $dbhandler->prepare("DESCRIBE $tblName");
		$stmt->execute();
		$response->withJson($stmt->fetchAll(),  201)->withHeader('Content-Type', 'application/json');
		return $response;
        
    });
});


/**
 * User Login
 * url - /login
 * method - POST
 * params - email, password
 */
$app->post('/login', function($request, $response, $args) {

	$status = false;

	$dbhandler = $this->db;
	$email = $request->getParam('email');
	$password = $request->getParam('password');

    //if ( $db_password != "") {
	if( filter_var($email, FILTER_VALIDATE_EMAIL) ){
		if ( does_email_exist($dbhandler, $email) ){
	       	// Found user with the email
	        // Now verify the password

	        //if (PassHash::check_password($password_hash, $password)) {
	        if( check_user_credential($dbhandler, $email, $password) ){
	         	// User password is correct
	         	$code = 1;
	         	$status = true;
	         	$data = "Username successfully logged in";

	         	$information = get_user_detail($dbhandler,$email)[0];

	         	//print_r($information);
	         	//return;

	         	$message = array('code' => $code , 'status' => $status, 'data'=> $data, 'information' => $information );
	         	$response->withJson($message);
	            return $resposne;
	        } else {
	            // user password is incorrect
	            $code = 0;
	            $data = "Username and Password does not match";
	            $message = array('code' => $code , 'status' => $status, 'data'=> $data );
	         	$response->withJson($message);
	            return $response;
	        }
	    }else {
	        // user not existed with the email
	        $code = 2;
	        $data = "User does not exist";
	        $message = array('code' => $code , 'status' => $status, 'data'=> $data );
	        $response->withJson($message);
	        return $response;
	    }
	}
	else{
		// not a valid email address
	        $code = 3;
	        $data = "Not a valid Email address";
	        $message = array('code' => $code , 'status' => $status, 'data'=> $data );
	        $response->withJson($message);
	        return $response;
	}
    
});

/**
 * User Registration
 * url - /register
 * method - POST
 * params - name, email, password, address, contact, assign_type, type, status = 1
 */
$app->post('/register', function($request, $response, $args) {

	$status = false;

	$dbhandler = $this->db;
	$email = $request->getParam('email');
	$password = $request->getParam('password');
	$name = $request->getParam('name');
	$address = $request->getParam('address');
	$contact = $request->getParam('contact');
	$assign_type = $request->getParam('assign_type');
	$type = $request->getParam('type');

	

	if( filter_var($email, FILTER_VALIDATE_EMAIL) ){
		if( does_email_exist($dbhandler, $email) ){
				$code = 0;
				$data = "Email Already Exist";
				$message = $message = array('code' => $code , 'status' => $status, 'data'=> $data );
				$response->withJson($message);
				return $response;
			
		}else{
			if( create_user($dbhandler, $name, $email, $password, $address, $contact, $assign_type, $type)){
				$status = true;
				$code = 1;
				$data = "User successfully Created";

				$information = get_user_detail($dbhandler,$email)[0];

				$message = $message = array('code' => $code , 'status' => $status, 'data'=> $data , 'information' => $information );
				$response->withJson($message);
				return $response;
			}
			else{
				$code = 2;
				$data = "Server error, Try again later";
				$message = $message = array('code' => $code , 'status' => $status, 'data'=> $data );
				$response->withJson($message);
				return $response;
			}
		}
	}else{
		$code = 3;
		$data = "Email invalide";
		$message = array('code' => $code , 'status' => $status, 'data'=> $data );
		$response->withJson($message);
		return $response;
	}
	
});


/**
===============================================================================================
===============================================================================================
*/

/**
* Function to check email for registration
*/
function does_email_exist($dbhandler, $email){

	$stmt = $dbhandler->prepare("SELECT id FROM tbl_user WHERE username = :email");
	$stmt->bindParam(":email",$email);
	$stmt->execute();

	$id = $stmt->fetchAll();
	if(!empty($id))
		return true;
	else
		return false;
}

/**
* Function to check login
*/

function check_user_credential($dbhandler, $email, $password){

	$stmt = $dbhandler->prepare("SELECT password FROM tbl_user WHERE username = :email");
	$stmt->bindParam(":email",$email);
	$stmt->execute();

    $db_password = $stmt->fetchAll();

    $db_password = $db_password[0]['password'];

    if( PassHash::check_password($db_password, $password))
    	return true;
    else
    	return false;
}

/**
* Function to check login
*/
function get_user_detail($dbhandler,$email){
	$information = $dbhandler->prepare("SELECT 
							id,
							username,
							name,
							address,
							contact,
							auth,
							assign_type,
							type,
							status
							FROM tbl_user WHERE username = :email");

         	$information->bindParam(":email",$email);
			$information->execute();

			$information = $information->fetchAll();

			return($information);
}

/**
* Function to create a new user in Database
*/

function create_user($dbhandler,$name,$email,$password, $address, $contact, $assign_type, $type){

	$stmt = $dbhandler->prepare("INSERT INTO tbl_user(name, username, password, address, contact, auth, assign_type, type, status) values(:name, :username, :password, :address, :contact, :auth, :assign_type, :type, 1)");
	$stmt->bindParam(":name",$name);
	$stmt->bindParam(":username",$email);
	$stmt->bindParam(":password",$password);
	$stmt->bindParam(":address",$address);
	$stmt->bindParam(":contact",$contact);
	$stmt->bindParam(":auth", generate_api_key());
	$stmt->bindParam(":assign_type",$assign_type);
	$stmt->bindParam(":type",$type);
	return $stmt->execute();
}

/**
* Valide email
*/
function validate_email($email) {
    
}

/**
* Generate Auth code
*/
function generate_api_key() {
	return md5(uniqid(rand(), true));
}

/**
* Function to encrypt Password
*/
class PassHash {

    // blowfish
    private static $algo = '$2a';
    // cost parameter
    private static $cost = '$10';

    // mainly for internal use
    public static function unique_salt() {
        return substr(sha1(mt_rand()), 0, 22);
    }

    // this will be used to generate a hash
    public static function hash($password) {

        return crypt($password, self::$algo .
                self::$cost .
                '$' . self::unique_salt());
    }

    // this will be used to compare a password against a hash
    // public static function check_password($hash, $password) {
    //     $full_salt = substr($hash, 0, 29);
    //     $new_hash = crypt($password, $full_salt);
    //     return ($hash == $new_hash);
    // }

    // for time being no Hashing the Password
    public static function check_password($hash, $password){
    	return ($hash == $password);
    }

}







