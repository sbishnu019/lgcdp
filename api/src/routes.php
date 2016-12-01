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
		$response->withJson($stmt->fetchAll(),  201)->withHeader('Content-Type', 'application/json');
		return $response;
        
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
		$response->withJson($stmt->fetchAll(), 201)->withHeader('Content-Type', 'application/json');
		return $response;
        
    });
});


/**
	 * Group route for SM list
	 * url - /api/sm/{option}
	 * method - GET
	 * params - 
	 */

$app->group('/api/sm', function () {
	/**
	 * Get sm list of certain district
	 * url - /api/sm/district/{$district}
	 * method - GET
	 * params - district name
	 */
	$this->get('/district/{district}',function($request,$response,$args){
		$district = $request->getAttribute("district");
		$dbhandler=$this->db;
		$stmt = $dbhandler->prepare("SELECT id FROM tbl_district WHERE name_en=\"$district\"");
		$stmt->execute();
		$id=$stmt->fetch(PDO::FETCH_ASSOC);
		$district_id = $id['id'];
		$nextStmt=$dbhandler->prepare("SELECT name FROM tbl_sm WHERE district_id=$district_id ORDER BY id ASC");
		$nextStmt->execute();
		$response->withJson($nextStmt->fetchAll());
		return $response;
	});

	/**
	 * Get sm list of certain municipality
	 * url - /api/sm/munic/{$municipality}
	 * method - GET
	 * params - municipality name
	 */
	$this->get('/munic/{municipality}',function($request,$response,$args){
		$municipality = $request->getAttribute("municipality");
		$dbhandler=$this->db;
		$stmt = $dbhandler->prepare("SELECT id FROM tbl_district WHERE name_en=\"$municipality\" and type =\"M\"");
		$stmt->execute();
		$id=$stmt->fetch(PDO::FETCH_ASSOC);
		$district_id = $id['id'];
		$nextStmt=$dbhandler->prepare("SELECT name FROM tbl_sm WHERE district_id=$district_id ORDER BY id ASC");
		$nextStmt->execute();
		$response->withJson($nextStmt->fetchAll());
		return $response;
	});

	/**
	 * Get other regional sm list 
	 * url - /api/sm/regionalOther
	 * method - GET
	 * params - none
	 */
	$this->get('/regionalother',function($request,$response,$args){
		$dbhandler=$this->db;
		$nextStmt=$dbhandler->prepare("SELECT name FROM tbl_sm_other ORDER BY id ASC");
		$nextStmt->execute();
		$response->withJson($nextStmt->fetchAll());
		return $response;
	});
});

/**
	 * Group route for lsp list
	 * url - /api/lsp/{option}
	 * method - GET
	 * params - 
	 */

$app->group('/api/lsp', function () {
	/**
	 * Get lsp list of certain district
	 * url - /api/lsp/district/{$district}
	 * method - GET
	 * params - district name
	 */
	$this->get('/district/{district}',function($request,$response,$args){
		$district = $request->getAttribute("district");
		$dbhandler=$this->db;
		$stmt = $dbhandler->prepare("SELECT id FROM tbl_district WHERE name_en=\"$district\"");
		$stmt->execute();
		$id=$stmt->fetch(PDO::FETCH_ASSOC);
		$district_id = $id['id'];
		$nextStmt=$dbhandler->prepare("SELECT name FROM tbl_lsp WHERE district_id=$district_id ORDER BY id ASC");
		$nextStmt->execute();
		$response->withJson($nextStmt->fetchAll());
		return $response;
	});

	/**
	 * Get sm list of certain municipality
	 * url - /api/lsp/munic/{$municipality}
	 * method - GET
	 * params - municipality name
	 */
	$this->get('/munic/{municipality}',function($request,$response,$args){
		$municipality = $request->getAttribute("municipality");
		$dbhandler=$this->db;
		$stmt = $dbhandler->prepare("SELECT id FROM tbl_district WHERE name_en=\"$municipality\" and type =\"M\"");
		$stmt->execute();
		$id=$stmt->fetch(PDO::FETCH_ASSOC);
		$district_id = $id['id'];
		$nextStmt=$dbhandler->prepare("SELECT name FROM tbl_lsp WHERE district_id=$district_id ORDER BY id ASC");
		$nextStmt->execute();
		$response->withJson($nextStmt->fetchAll());
		return $response;
	});
});



/**
	 * Group route for detail of anything
	 * url - /api/detail/
	 * method - GET
	 * params - 
	 */

$app->group('/api/detail/', function () {
	/**
	 * Get detail of certain sm
	 * url - /api/detail/sm/{$smName}
	 * method - GET
	 * params - sm name
	 */
	$this->get('sm/{smName}',function($request,$response,$args){
		$smName = $request->getAttribute("smName");
		$dbhandler=$this->db;
		$nextStmt=$dbhandler->prepare("SELECT * FROM tbl_sm WHERE name =\"$smName\"");
		$nextStmt->execute();
		$response->withJson($nextStmt->fetch(PDO::FETCH_ASSOC));
		return $response;
	});

	/**
	 * Get detail of other regional sm
	 * url - /api/detail/othersm/{$smName}
	 * method - GET
	 * params - sm name
	 */
	$this->get('othersm/{smName}',function($request,$response,$args){
		$smName = $request->getAttribute("smName");
		$dbhandler=$this->db;
		$nextStmt=$dbhandler->prepare("SELECT * FROM tbl_sm_other WHERE name =\"$smName\"");
		$nextStmt->execute();
		$response->withJson($nextStmt->fetch(PDO::FETCH_ASSOC));
		return $response;
	});

	/**
	 * Get detail of certain lsp
	 * url - /api/detail/lsp/{$lspName}
	 * method - GET
	 * params - lsp name
	 */
	$this->get('lsp/{lspName}',function($request,$response,$args){
		$lspName = $request->getAttribute("lspName");
		$dbhandler=$this->db;
		$nextStmt=$dbhandler->prepare("SELECT * FROM tbl_lsp WHERE name =\"$lspName\"");
		$nextStmt->execute();
		$response->withJson($nextStmt->fetch(PDO::FETCH_ASSOC));
		return $response;
	});
});



$app->get('/munic',function($request, $response, $args){
	$dbhandler = $this->db;
	//$stmt = $dbhandler->prepare("SELECT name FROM tbl_sm WHERE district_id=39 ORDER BY name ASC");
	//$stmt = $dbhandler->prepare("SELECT name FROM tbl_sm ORDER BY name ASC");
	$stmt = $dbhandler->prepare("SELECT name_en FROM munici2 ORDER BY name_en ASC");
	$stmt->execute();
	$response->withJson($stmt->fetchAll());
	return $response;
});
/**
	 * Group route for list municipality/district
	 * url - /api/list/
	 * method - GET
	 * params - 
	 */

$app->group('/api/list/', function () {
	/**
	 * Get list of all municipality
	 * url - /api/detail/munic
	 * method - GET
	 * params - 
	 */
	$this->get('munic',function($request, $response, $args){
		$dbhandler = $this->db;
		$stmt = $dbhandler->prepare("SELECT name_en FROM munici2 ORDER BY name_en ASC");
		$stmt->execute();
		$response->withJson($stmt->fetchAll());
		return $response;
	});

	/**
	 * Get list of all district
	 * url - /api/list/district
	 * method - GET
	 * params - 
	 */

	$this->get('district',function($request, $response, $args){
		$dbhandler = $this->db;
		//$stmt = $dbhandler->prepare("SELECT name_en FROM tbl_district WHERE type=\"D\" ORDER BY name_en ASC");
		//$stmt->execute();
		$response->withJson($stmt->fetchAll());
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
 * params - name, email, password, address, contact
 */

$app->post('/register', function($request, $response, $args) {

	$status = false;

	$dbhandler = $this->db;
	$email = $request->getParam('email');
	$password = $request->getParam('password');
	$name = $request->getParam('name');
	$address = $request->getParam('address');
	$contact = $request->getParam('contact');

	

	if( filter_var($email, FILTER_VALIDATE_EMAIL) ){
		if( does_email_exist($dbhandler, $email) ){
				$code = 0;
				$data = "Email Already Exist";
				$message = $message = array('code' => $code , 'status' => $status, 'data'=> $data );
				$response->withJson($message);
				return $response;
			
		}else{
			if( create_user($dbhandler, $name, $email, $password, $address, $contact)){
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
		$response->withJson($message, 200);
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
							auth
							FROM tbl_user WHERE username = :email");

         	$information->bindParam(":email",$email);
			$information->execute();

			$information = $information->fetchAll();

			return($information);
}

/**
* Function to create a new user in Database
*/

function create_user($dbhandler,$name,$email,$password, $address, $contact){

	$stmt = $dbhandler->prepare("INSERT INTO tbl_user(name, username, password, address, contact, auth) values(:name, :username, :password, :address, :contact, :auth)");
	$stmt->bindParam(":name",$name);
	$stmt->bindParam(":username",$email);
	$stmt->bindParam(":password",$password);
	$stmt->bindParam(":address",$address);
	$stmt->bindParam(":contact",$contact);
	$stmt->bindParam(":auth", generate_api_key());
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







