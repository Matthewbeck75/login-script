<?php

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
		
session_start();
	    session_destroy();
	    session_unset();
		
		$params = session_get_cookie_params();	
		if ($params['httponly'] != TRUE) {
					session_set_cookie_params(NULL, NULL, NULL, TRUE, TRUE); //secure only (set to true) / http only
					}
		session_start();
	
		
		$postdata = array();
		parse_str($_POST['data'], $postdata); //Puts all form data into $postdata array
		$errors = array();
		require('../mysqli.php');
		
		
		if (isset($_SESSION['user_ID'])) { //if user is already logged in then exit
		$data = array(
						'status' => 'Failure', 
						'reason' => "Already logged in - refresh the page"
						);	
		echo json_encode($data);
		exit();	
		}
		
		$attempts = isset($_SESSION['attempts']) ? $_SESSION['attempts'] : 0; //set attempts to 0 if it does not exist
		if (isset($_SESSION['locked']) && time() - $_SESSION['locked'] > 900) { //if 15 minutes has elapsed since creation of session['locked']
				unset($_SESSION['locked']); //undo lock and reset attempts
				$attempts = 0;
			} 
		if ($attempts <= 5) {
			$attempts ++; //new attempts so +1
		if (empty($postdata['signin_email'])) {
			$errors[] = 'No username or email given';
		} else { //if not empty
			if (filter_var($postdata['signin_email'], FILTER_VALIDATE_EMAIL) == TRUE) { //if an email
			$signin_email = $mysqli->real_escape_string(substr($postdata['signin_email'], 0, 200));
			$signin_type = 'email';
			$where = "email = '" . $signin_email . "'";
			} else { //if not an email and therefore a username
			$signin_email = $mysqli->real_escape_string(substr($postdata['signin_email'], 0, 30));
			$signin_type = 'username';	
			$where = "username = '" . $signin_email . "'";
			}
			$q = "SELECT salt FROM users WHERE $where LIMIT 1"; 
			$r = $mysqli->query($q);
			$numrows = mysqli_num_rows($r);
			
			if ($numrows == 1){
			$mod = $r->fetch_assoc();
			$fetched_salt = $mod['salt'];
			} else {
				$errors[] = 'Username or Email does not exist';
			}
		}
		if (empty($postdata['signin_password'])) {
			$errors[] = 'No password given';
		} 
		
		if (empty($errors)) { //then go ahead with username check
			$salted = $fetched_salt . $postdata['signin_password'];
			$password_hashed = hash('SHA256', $salted);
			
			$signin_email = $mysqli->real_escape_string($signin_email);
			$q = "SELECT ID, username FROM users_table WHERE $where AND password = '$password_hashed' LIMIT 1";
			$r = $mysqli->query($q);
			$numrows = mysqli_num_rows($r);
			if ($numrows == 1) { //if row returned therefore username and password match those entered
				$auth = $r->fetch_assoc();
				$ID = $auth['ID'];
			
				
				$_SESSION['user_ID'] = $auth['ID'];
				$_SESSION['email'] = $auth['email'];
				$_SESSION['username'] = $auth['username'];
				$attempts = 0;
					
				$data = array(
						'status' => 'Success', 
						'username' => $auth['username']
						);
						
				$email = $auth['email'];		
				$IP = $_SERVER['REMOTE_ADDR'];//set log of login
				$a = "INSERT INTO user_login (`user_ID`, `IP`) VALUES ('$ID', '$IP')";
				$r = $mysqli->query($a);				
			} else { //else no match therefore login attempt failed.				
				$data = array(
						'status' => 'Failure', 
						'reason' => 'Login failed, incorrect combination.',
						'attempt' => "$attempts"
						);
			}
			
		} else { //else errors in previous validation, happens if username or email does not exist
				
				$data = array(
						'status' => 'Failure', 
						'reason' => 'Login failed, incorrect combination.',
						'attempt' => "$attempts"
						);
		}
		} else { //if attempts is higher than 5 {
			if (!isset($_SESSION['locked'])) { //if not already locked then create that now
			$_SESSION['locked'] = time();
			} 
			$remainingtime = ceil(15 -(time() - $_SESSION['locked']) / 60); //remaining time of lockout in minutes (lockout is 15 mins)
			if ($remainingtime >= 2) {
				$xmins = "$remainingtime minutes";
			} else {
				$xmins = "a minute or less";
			}
			$data = array(
						'status' => 'Failure', 
						'reason' => "You have been locked out for $xmins",
						'until' => "$remainingtime"
						);
		
		}
		$_SESSION['attempts'] = $attempts;		

echo json_encode($data);
}

?>
