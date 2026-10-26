<?php

$secureCookie = !empty($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] !== "off";
session_set_cookie_params([
    "httponly" => true,
    "samesite" => "Lax",
    "secure" => $secureCookie,
]);
session_start();

if (!isset($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}

$message = "";
$messageType = "error";
$lastName = "";
$firstName = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $lastName = trim($_POST["last_name"] ?? "");
    $firstName = trim($_POST["first_name"] ?? "");
    $action = $_POST["action"] ?? "";

    if (!hash_equals($_SESSION["csrf_token"], $_POST["csrf_token"] ?? "")) {
        http_response_code(400);
        $message = "La demande a expiré. Rechargez la page et réessayez.";
    } elseif ($action === "logout") {
        unset($_SESSION["user_id"], $_SESSION["user_name"]);
        session_regenerate_id(true);
        $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
        $message = "Vous êtes déconnecté.";
        $messageType = "success";
    } else {
        try {
            $dbh = new PDO(
                "mysql:host=localhost;dbname=guardia.cs;charset=utf8mb4",
                "root",
                "",
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
            );

            if ($action === "register") {
                $password = $_POST["password"] ?? "";
                $passwordConfirmation = $_POST["password_confirmation"] ?? "";

                if ($lastName === "" || $firstName === "" || mb_strlen($lastName) > 100 || mb_strlen($firstName) > 100) {
                    $message = "Saisissez un nom et un prénom de 100 caractères maximum.";
                } elseif (strlen($password) < 8) {
                    $message = "Le mot de passe doit contenir au moins 8 caractères.";
                } elseif ($password !== $passwordConfirmation) {
                    $message = "Les mots de passe ne correspondent pas.";
                } else {
                    $existingUser = $dbh->prepare(
                        "SELECT Id_utilisateur FROM utilisateur WHERE Nom = :last_name AND `Prénom` = :first_name"
                    );
                    $existingUser->execute([
                        "last_name" => $lastName,
                        "first_name" => $firstName,
                    ]);

                    if ($existingUser->fetch()) {
                        $message = "Un compte avec ce nom et ce prénom existe déjà.";
                    } else {
                        $createUser = $dbh->prepare(
                            "INSERT INTO utilisateur (Nom, `Prénom`, Mot_de_passe) VALUES (:last_name, :first_name, :password)"
                        );
                        $createUser->execute([
                            "last_name" => $lastName,
                            "first_name" => $firstName,
                            "password" => password_hash($password, PASSWORD_DEFAULT),
                        ]);

                        session_regenerate_id(true);
                        $_SESSION["user_id"] = (int) $dbh->lastInsertId();
                        $_SESSION["user_name"] = $firstName . " " . $lastName;
                        $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
                        $message = "Votre compte a été créé. Vous êtes connecté.";
                        $messageType = "success";
                    }
                }
            } elseif ($action === "login") {
                $password = $_POST["password"] ?? "";

                if ($lastName === "" || $firstName === "" || $password === "") {
                    $message = "Saisissez votre nom, votre prénom et votre mot de passe.";
                } else {
                    $findUser = $dbh->prepare(
                        "SELECT Id_utilisateur, Nom, `Prénom`, Mot_de_passe FROM utilisateur WHERE Nom = :last_name AND `Prénom` = :first_name"
                    );
                    $findUser->execute([
                        "last_name" => $lastName,
                        "first_name" => $firstName,
                    ]);
                    $user = $findUser->fetch(PDO::FETCH_ASSOC);

                    if ($user && !empty($user["Mot_de_passe"]) && password_verify($password, $user["Mot_de_passe"])) {
                        session_regenerate_id(true);
                        $_SESSION["user_id"] = (int) $user["Id_utilisateur"];
                        $_SESSION["user_name"] = $user["Prénom"] . " " . $user["Nom"];
                        $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
                        $message = "Connexion réussie.";
                        $messageType = "success";
                    } else {
                        $message = "Nom, prénom ou mot de passe incorrect.";
                    }
                }
            } else {
                http_response_code(400);
                $message = "Action non reconnue.";
            }
        } catch (PDOException $exception) {
            error_log("Erreur guardians.php : " . $exception->getMessage());
            http_response_code(500);
            $message = "Impossible de contacter la base de données. Vérifiez que MySQL est démarré.";
        }
    }
}

function escapeHtml($value)
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8");
}

?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Connexion - MonEvent</title>
    <link rel="stylesheet" href="style.css" />
    <style>
        main {
            width: min(900px, calc(100% - 32px));
            margin: 48px auto;
        }
        .auth-panels {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(min(100%, 300px), 1fr));
            gap: 24px;
        }
        .auth-panel {
            padding: 24px;
            border: 1px solid #e3e7df;
            border-radius: 12px;
            background: #fff;
        }
        .auth-panel h1,
        .auth-panel h2 {
            margin-top: 0;
        }
        .auth-panel label {
            display: block;
            margin-top: 14px;
            font-weight: 600;
        }
        .auth-panel input {
            display: block;
            width: 100%;
            min-height: 42px;
            margin-top: 4px;
            padding: 8px 10px;
            border: 1px solid #888;
            border-radius: 6px;
            font: inherit;
        }
        .auth-panel button {
            margin-top: 20px;
            padding: 10px 16px;
            border: 0;
            border-radius: 6px;
            background: #070707;
            color: #fff;
            cursor: pointer;
            font: inherit;
        }
        .message {
            margin-bottom: 24px;
            padding: 12px 16px;
            border-radius: 6px;
            background: #fff;
        }
        .message.error {
            border: 1px solid #b42318;
            color: #8f1d14;
        }
        .message.success {
            border: 1px solid #16803c;
            color: #12632f;
        }
        .back-link {
            display: inline-block;
            margin-top: 24px;
        }
    </style>
</head>
<body>
<main>
    <h1>Connexion à MonEvent</h1>

    <?php if ($message !== ""): ?>
        <p class="message <?= escapeHtml($messageType) ?>" role="status"><?= escapeHtml($message) ?></p>
    <?php endif; ?>

    <?php if (isset($_SESSION["user_id"])): ?>
        <section class="auth-panel">
            <h2>Bienvenue <?= escapeHtml($_SESSION["user_name"] ?? "") ?> !</h2>
            <p>Vous êtes connecté à votre compte MonEvent.</p>
            <form method="post" action="guardians.php">
                <input type="hidden" name="csrf_token" value="<?= escapeHtml($_SESSION["csrf_token"]) ?>" />
                <button type="submit" name="action" value="logout">Se déconnecter</button>
            </form>
        </section>
    <?php else: ?>
        <div class="auth-panels">
            <section class="auth-panel">
                <h2>Se connecter</h2>
                <form method="post" action="guardians.php">
                    <input type="hidden" name="csrf_token" value="<?= escapeHtml($_SESSION["csrf_token"]) ?>" />
                    <label for="login-last-name">Nom</label>
                    <input id="login-last-name" name="last_name" maxlength="100" autocomplete="family-name" required value="<?= escapeHtml($lastName) ?>" />
                    <label for="login-first-name">Prénom</label>
                    <input id="login-first-name" name="first_name" maxlength="100" autocomplete="given-name" required value="<?= escapeHtml($firstName) ?>" />
                    <label for="login-password">Mot de passe</label>
                    <input id="login-password" name="password" type="password" autocomplete="current-password" required />
                    <button type="submit" name="action" value="login">Se connecter</button>
                </form>
            </section>

            <section class="auth-panel">
                <h2>Créer un compte</h2>
                <form method="post" action="guardians.php">
                    <input type="hidden" name="csrf_token" value="<?= escapeHtml($_SESSION["csrf_token"]) ?>" />
                    <label for="register-last-name">Nom</label>
                    <input id="register-last-name" name="last_name" maxlength="100" autocomplete="family-name" required value="<?= escapeHtml($lastName) ?>" />
                    <label for="register-first-name">Prénom</label>
                    <input id="register-first-name" name="first_name" maxlength="100" autocomplete="given-name" required value="<?= escapeHtml($firstName) ?>" />
                    <label for="register-password">Mot de passe (8 caractères minimum)</label>
                    <input id="register-password" name="password" type="password" minlength="8" autocomplete="new-password" required />
                    <label for="register-password-confirmation">Confirmer le mot de passe</label>
                    <input id="register-password-confirmation" name="password_confirmation" type="password" minlength="8" autocomplete="new-password" required />
                    <button type="submit" name="action" value="register">Créer mon compte</button>
                </form>
            </section>
        </div>
    <?php endif; ?>

    <a class="back-link" href="index.html">Retour à l’accueil</a>
</main>
</body>
</html>
