<?php
// Database Configuration
define('DB_SERVER', 'localhost'); // or your db host
define('DB_USERNAME', 'root');    // your db username
define('DB_PASSWORD', '');        // your db password
define('DB_NAME', 'spin_earn_db'); // your database name

// Start session
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Error Reporting (for development)
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
?>
```

**`php/db.php`**
```php
<?php
require_once 'config.php';

function getDbConnection() {
    $conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
    if ($conn->connect_error) {
        // Log error and die, or handle more gracefully in production
        error_log("Connection failed: " . $conn->connect_error);
        die(json_encode(['success' => false, 'message' => 'Database connection error. Please try again later.']));
    }
    $conn->set_charset("utf8mb4");
    return $conn;
}

function generateReferralCode($length = 8) {
    $characters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    // Ensure uniqueness (simple check, can be more robust)
    $conn = getDbConnection();
    $stmt = $conn->prepare("SELECT id FROM users WHERE referral_code = ?");
    $stmt->bind_param("s", $randomString);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows > 0) {
        return generateReferralCode($length); // Recurse if not unique
    }
    $stmt->close();
    $conn->close();
    return $randomString;
}

function addActivityLog($userId, $description, $type, $pointsChange = 0, $value = null) {
    $conn = getDbConnection();
    $stmt = $conn->prepare("INSERT INTO activity_log (user_id, description, type, points_change, value) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("issis", $userId, $description, $type, $pointsChange, $value);
    $success = $stmt->execute();
    $stmt->close();
    $conn->close();
    return $success;
}

function getUserData($userId) {
    $conn = getDbConnection();
    $stmt = $conn->prepare("SELECT id, username, email, points, spins_left, slot_tokens, scratch_cards_left, last_daily_bonus_claimed, referral_code, DATE_FORMAT(member_since, '%Y-%m-%d') as member_since FROM users WHERE id = ?");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $result = $stmt->get_result();
    $userData = $result->fetch_assoc();
    $stmt->close();
    $conn->close();
    return $userData;
}
?>
```

**`php/api.php`**
```php
<?php
require_once 'config.php';
require_once 'db.php';

header('Content-Type: application/json');

$action = $_POST['action'] ?? $_GET['action'] ?? '';

if (!$action) {
    echo json_encode(['success' => false, 'message' => 'No action specified.']);
    exit;
}

$conn = getDbConnection();

switch ($action) {
    case 'register':
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirmPassword = $_POST['confirmPassword'] ?? '';

        if (empty($username) || empty($password) || empty($confirmPassword)) {
            echo json_encode(['success' => false, 'message' => 'All fields are required.']);
            exit;
        }
        if (strlen($username) < 3 || !preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
            echo json_encode(['success' => false, 'message' => 'Username must be at least 3 characters and contain only letters, numbers, and underscores.']);
            exit;
        }
        if (strlen($password) < 6) {
            echo json_encode(['success' => false, 'message' => 'Password must be at least 6 characters.']);
            exit;
        }
        if ($password !== $confirmPassword) {
            echo json_encode(['success' => false, 'message' => 'Passwords do not match.']);
            exit;
        }

        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows > 0) {
            echo json_encode(['success' => false, 'message' => 'Username already exists.']);
        } else {
            $password_hash = password_hash($password, PASSWORD_DEFAULT);
            $referral_code = generateReferralCode();
            $stmt_insert = $conn->prepare("INSERT INTO users (username, password_hash, referral_code, points, spins_left, slot_tokens, scratch_cards_left) VALUES (?, ?, ?, 100, 5, 10, 3)");
            $stmt_insert->bind_param("sss", $username, $password_hash, $referral_code);
            if ($stmt_insert->execute()) {
                $userId = $stmt_insert->insert_id;
                addActivityLog($userId, "Account registered successfully. Welcome!", 'register', 100);
                echo json_encode(['success' => true, 'message' => 'Registration successful! Please login.']);
            } else {
                echo json_encode(['success' => false, 'message' => 'Registration failed. Please try again. Error: ' . $stmt_insert->error]);
            }
            $stmt_insert->close();
        }
        $stmt->close();
        break;

    case 'login':
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        if (empty($username) || empty($password)) {
            echo json_encode(['success' => false, 'message' => 'Username and password are required.']);
            exit;
        }

        $stmt = $conn->prepare("SELECT id, username, password_hash FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($user = $result->fetch_assoc()) {
            if (password_verify($password, $user['password_hash'])) {
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                addActivityLog($user['id'], "Logged in successfully.", 'login');
                echo json_encode(['success' => true, 'message' => 'Login successful!', 'user' => getUserData($user['id'])]);
            } else {
                echo json_encode(['success' => false, 'message' => 'Invalid username or password.']);
            }
        } else {
            echo json_encode(['success' => false, 'message' => 'Invalid username or password.']);
        }
        $stmt->close();
        break;

    case 'logout':
        if (isset($_SESSION['user_id'])) {
            addActivityLog($_SESSION['user_id'], "Logged out.", 'logout');
        }
        session_unset();
        session_destroy();
        echo json_encode(['success' => true, 'message' => 'Logged out successfully.']);
        break;

    case 'check_session':
        if (isset($_SESSION['user_id'])) {
            echo json_encode(['success' => true, 'isLoggedIn' => true, 'user' => getUserData($_SESSION['user_id'])]);
        } else {
            echo json_encode(['success' => true, 'isLoggedIn' => false]);
        }
        break;

    case 'get_user_data': // For refreshing data if needed, though check_session and game actions return it
        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['success' => false, 'message' => 'Not logged in.']);
            exit;
        }
        echo json_encode(['success' => true, 'user' => getUserData($_SESSION['user_id'])]);
        break;

    case 'spin_wheel':
        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['success' => false, 'message' => 'Please login to spin.']);
            exit;
        }
        $userId = $_SESSION['user_id'];
        $currentUserData = getUserData($userId);

        if ($currentUserData['spins_left'] <= 0) {
            echo json_encode(['success' => false, 'message' => 'No spins left.']);
            exit;
        }

        // Server-side prize determination
        $spinWheelSegmentsData = [
            ["label" => "10 Pts", "value" => 10, "type" => "points"], ["label" => "Try Again", "value" => 0, "type" => "points"],
            ["label" => "50 Pts", "value" => 50, "type" => "points"], ["label" => "Bonus Spin", "value" => 1, "type" => "bonus_spin"],
            ["label" => "20 Pts", "value" => 20, "type" => "points"], ["label" => "No Luck", "value" => 0, "type" => "points"],
            ["label" => "100 Pts", "value" => 100, "type" => "points"], ["label" => "5 Pts", "value" => 5, "type" => "points"],
        ];
        $randomIndex = array_rand($spinWheelSegmentsData);
        $winningSegment = $spinWheelSegmentsData[$randomIndex];

        $newSpinsLeft = $currentUserData['spins_left'] - 1;
        $newPoints = $currentUserData['points'];
        $activityDesc = "";
        $activityType = 'spin_loss';
        $pointsChange = 0;

        if ($winningSegment['type'] === 'bonus_spin') {
            $newSpinsLeft++;
            $activityDesc = "Won a Bonus Spin from the wheel.";
            $activityType = 'spin_bonus';
        } elseif ($winningSegment['type'] === 'points' && $winningSegment['value'] > 0) {
            $newPoints += $winningSegment['value'];
            $pointsChange = $winningSegment['value'];
            $activityDesc = "Won {$winningSegment['value']} points from the wheel.";
            $activityType = 'spin_win';
        } else {
             $activityDesc = "Wheel spin resulted in '{$winningSegment['label']}'.";
        }
        
        $stmt = $conn->prepare("UPDATE users SET points = ?, spins_left = ? WHERE id = ?");
        $stmt->bind_param("iii", $newPoints, $newSpinsLeft, $userId);
        $stmt->execute();

        addActivityLog($userId, $activityDesc, $activityType, $pointsChange, $winningSegment['label']);
        echo json_encode(['success' => true, 'winningSegment' => $winningSegment, 'user' => getUserData($userId)]);
        $stmt->close();
        break;

    case 'play_slot':
        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['success' => false, 'message' => 'Please login to play slots.']);
            exit;
        }
        $userId = $_SESSION['user_id'];
        $currentUserData = getUserData($userId);

        if ($currentUserData['slot_tokens'] <= 0) {
            echo json_encode(['success' => false, 'message' => 'No slot tokens left.']);
            exit;
        }
        
        $newSlotTokens = $currentUserData['slot_tokens'] - 1;
        addActivityLog($userId, "Played Slot Machine (1 token spent).", 'slot_play', 0, "1 Token");


        // Server-side slot result determination
        $slotSymbols = ['🍒', '🍋', '🍊', '🍉', '⭐', '７', '🔔'];
        $reelResultsIndices = [array_rand($slotSymbols), array_rand($slotSymbols), array_rand($slotSymbols)];
        $reelSymbols = [$slotSymbols[$reelResultsIndices[0]], $slotSymbols[$reelResultsIndices[1]], $slotSymbols[$reelResultsIndices[2]]];

        $winAmount = 0;
        $winMessage = "No Win";
        $s1 = $reelSymbols[0]; $s2 = $reelSymbols[1]; $s3 = $reelSymbols[2];

        if ($s1 === $s2 && $s2 === $s3) { // Three of a kind
            if ($s1 === '７') $winAmount = 500; elseif ($s1 === '⭐') $winAmount = 200;
            elseif ($s1 === '🍉') $winAmount = 100; elseif ($s1 === '🔔') $winAmount = 75;
            else $winAmount = 50;
            $winMessage = "JACKPOT! You won {$winAmount} points!";
        } elseif ($s1 === $s2 || $s2 === $s3 || $s1 === $s3) { // Two of a kind
            if ($s1 === $s2) { if ($s1 === '７') $winAmount = 20; elseif ($s1 === '⭐') $winAmount = 15; else $winAmount = 5; }
            elseif ($s2 === $s3) { if ($s2 === '７') $winAmount = 20; elseif ($s2 === '⭐') $winAmount = 15; else $winAmount = 5; }
            else { if ($s1 === '７') $winAmount = 10; elseif ($s1 === '⭐') $winAmount = 8; else $winAmount = 3; }
            $winMessage = "Match! You won {$winAmount} points.";
        }

        $newPoints = $currentUserData['points'] + $winAmount;
        $stmt = $conn->prepare("UPDATE users SET points = ?, slot_tokens = ? WHERE id = ?");
        $stmt->bind_param("iii", $newPoints, $newSlotTokens, $userId);
        $stmt->execute();

        if ($winAmount > 0) {
            addActivityLog($userId, "Won {$winAmount} points from Slot Machine. Reels: {$s1}{$s2}{$s3}", 'slot_win', $winAmount, "{$s1}{$s2}{$s3}");
        } else {
            addActivityLog($userId, "Slot Machine result: {$s1}{$s2}{$s3}. No win.", 'slot_loss', 0, "{$s1}{$s2}{$s3}");
        }
        echo json_encode(['success' => true, 'reelSymbols' => $reelSymbols, 'reelIndices' => $reelResultsIndices, 'winAmount' => $winAmount, 'winMessage' => $winMessage, 'user' => getUserData($userId)]);
        $stmt->close();
        break;

    case 'scratch_card':
        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['success' => false, 'message' => 'Please login to scratch.']);
            exit;
        }
        $userId = $_SESSION['user_id'];
        $currentUserData = getUserData($userId);

        if ($currentUserData['scratch_cards_left'] <= 0) {
            echo json_encode(['success' => false, 'message' => 'No scratch cards left.']);
            exit;
        }
        
        $newScratchCardsLeft = $currentUserData['scratch_cards_left'] - 1;
        
        // Server-side prize determination
        $prizes = [0, 5, 10, 25, 50, 100];
        $prizeWon = $prizes[array_rand($prizes)];
        $newPoints = $currentUserData['points'] + $prizeWon;

        $stmt = $conn->prepare("UPDATE users SET points = ?, scratch_cards_left = ? WHERE id = ?");
        $stmt->bind_param("iii", $newPoints, $newScratchCardsLeft, $userId);
        $stmt->execute();

        if ($prizeWon > 0) {
            addActivityLog($userId, "Won {$prizeWon} points from a scratch card.", 'scratch_win', $prizeWon, "{$prizeWon} Pts");
        } else {
            addActivityLog($userId, "Scratch card resulted in no win.", 'scratch_loss', 0, "No Win");
        }
        echo json_encode(['success' => true, 'prizeWon' => $prizeWon, 'user' => getUserData($userId)]);
        $stmt->close();
        break;

    case 'claim_daily_bonus':
        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['success' => false, 'message' => 'Please login to claim bonus.']);
            exit;
        }
        $userId = $_SESSION['user_id'];
        $currentUserData = getUserData($userId);
        $today = date("Y-m-d");

        if ($currentUserData['last_daily_bonus_claimed'] == $today) {
            echo json_encode(['success' => false, 'message' => "Bonus already claimed today."]);
            exit;
        }

        $bonusPoints = 25;
        $bonusSpins = 1;
        $newPoints = $currentUserData['points'] + $bonusPoints;
        $newSpins = $currentUserData['spins_left'] + $bonusSpins;

        $stmt = $conn->prepare("UPDATE users SET points = ?, spins_left = ?, last_daily_bonus_claimed = ? WHERE id = ?");
        $stmt->bind_param("iisi", $newPoints, $newSpins, $today, $userId);
        $stmt->execute();

        addActivityLog($userId, "Claimed daily bonus: {$bonusPoints} pts, {$bonusSpins} spin.", 'daily_bonus', $bonusPoints);
        echo json_encode(['success' => true, 'message' => "Successfully claimed {$bonusPoints} points and {$bonusSpins} spin!", 'user' => getUserData($userId)]);
        $stmt->close();
        break;

    case 'request_withdrawal':
        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['success' => false, 'message' => 'Please login to request withdrawal.']);
            exit;
        }
        $userId = $_SESSION['user_id'];
        $currentUserData = getUserData($userId);
        
        $amount = intval($_POST['amount'] ?? 0);
        $method = trim($_POST['method'] ?? '');
        $details = trim($_POST['details'] ?? '');

        if ($amount < 100) {
            echo json_encode(['success' => false, 'message' => 'Minimum withdrawal amount is 100 points.']);
            exit;
        }
        if ($amount > $currentUserData['points']) {
            echo json_encode(['success' => false, 'message' => 'Insufficient points balance.']);
            exit;
        }
        if (empty($method) || !in_array($method, ['paypal', 'bank', 'voucher'])) {
            echo json_encode(['success' => false, 'message' => 'Invalid withdrawal method.']);
            exit;
        }
        if (empty($details)) {
            echo json_encode(['success' => false, 'message' => 'Withdrawal details are required.']);
            exit;
        }

        $stmt = $conn->prepare("INSERT INTO withdrawal_requests (user_id, amount, method, details) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("iiss", $userId, $amount, $method, $details);
        
        if ($stmt->execute()) {
            $newPoints = $currentUserData['points'] - $amount;
            $stmt_update = $conn->prepare("UPDATE users SET points = ? WHERE id = ?");
            $stmt_update->bind_param("ii", $newPoints, $userId);
            $stmt_update->execute();
            $stmt_update->close();
            
            addActivityLog($userId, "Withdrawal request: {$amount} pts via {$method}.", 'redeem_request', -$amount, $method);
            echo json_encode(['success' => true, 'message' => 'Withdrawal request submitted successfully (Simulated).', 'user' => getUserData($userId)]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to submit withdrawal request.']);
        }
        $stmt->close();
        break;

    case 'get_history':
        if (!isset($_SESSION['user_id'])) {
            echo json_encode(['success' => false, 'message' => 'Please login to view history.']);
            exit;
        }
        $userId = $_SESSION['user_id'];
        $stmt = $conn->prepare("SELECT description, type, points_change, value, DATE_FORMAT(timestamp, '%Y-%m-%dT%H:%i:%sZ') as timestamp FROM activity_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT 50");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        $activities = [];
        while($row = $result->fetch_assoc()){
            $activities[] = $row;
        }
        echo json_encode(['success' => true, 'activities' => $activities]);
        $stmt->close();
        break;

    default:
        echo json_encode(['success' => false, 'message' => 'Invalid action.']);
        break;
}

$conn->close();
?>
