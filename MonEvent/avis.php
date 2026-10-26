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

function escapeHtml($value)
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8");
}

$eventName = "Concert de jazz";
$message = "";
$messageType = "error";
$reviewerName = $_SESSION["user_name"] ?? "";
$comment = "";
$rating = "";
$reviews = [];
$databaseError = false;

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $postedName = $_POST["reviewer_name"] ?? "";
    $postedComment = $_POST["comment"] ?? "";
    $postedToken = $_POST["csrf_token"] ?? "";
    $reviewerName = is_string($postedName) ? trim($postedName) : "";
    $comment = is_string($postedComment) ? trim($postedComment) : "";
    $postedRating = $_POST["rating"] ?? "";
    $rating = is_string($postedRating) ? $postedRating : "";
    $submittedRating = filter_var($rating, FILTER_VALIDATE_INT);

    if (!is_string($postedToken) || !hash_equals($_SESSION["csrf_token"], $postedToken)) {
        http_response_code(400);
        $message = "La demande a expiré. Rechargez la page et réessayez.";
    } elseif (
        $reviewerName === ""
        || mb_strlen($reviewerName) > 100
        || $comment === ""
        || mb_strlen($comment) > 2000
        || $submittedRating === false
        || $submittedRating < 1
        || $submittedRating > 5
    ) {
        http_response_code(422);
        $message = "Saisissez un nom (100 caractères maximum), une note de 1 à 5 et un commentaire (2 000 caractères maximum).";
    } else {
        $rating = $submittedRating;
    }
}

try {
    $dbh = new PDO(
        "mysql:host=localhost;dbname=guardia.cs;charset=utf8mb4",
        "root",
        "",
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );

    $dbh->exec(
        "CREATE TABLE IF NOT EXISTS avis (
            id_avis BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            evenement VARCHAR(150) NOT NULL,
            nom VARCHAR(100) NOT NULL,
            note TINYINT UNSIGNED NOT NULL,
            commentaire TEXT NOT NULL,
            date_creation TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_avis_evenement (evenement)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    );

    if ($_SERVER["REQUEST_METHOD"] === "POST" && $message === "") {
        $saveReview = $dbh->prepare(
            "INSERT INTO avis (evenement, nom, note, commentaire)
             VALUES (:event_name, :reviewer_name, :rating, :comment)"
        );
        $saveReview->execute([
            "event_name" => $eventName,
            "reviewer_name" => $reviewerName,
            "rating" => $rating,
            "comment" => $comment,
        ]);

        header("Location: avis.php?envoye=1#avis", true, 303);
        exit;
    }

    $findReviews = $dbh->prepare(
        "SELECT nom, note, commentaire, date_creation
         FROM avis
         WHERE evenement = :event_name
         ORDER BY date_creation DESC, id_avis DESC
         LIMIT 50"
    );
    $findReviews->execute(["event_name" => $eventName]);
    $reviews = $findReviews->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $exception) {
    error_log("Erreur avis.php : " . $exception->getMessage());
    http_response_code(500);
    $databaseError = true;
    $message = "Impossible d'accéder aux avis. Vérifiez que MySQL est démarré et que la base de données est disponible.";
    $messageType = "error";
}

if (isset($_GET["envoye"]) && $_GET["envoye"] === "1" && !$databaseError) {
    $message = "Merci, votre avis a bien été enregistré.";
    $messageType = "success";
}

?>
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Laissez et consultez les avis sur le concert de jazz MonEvent.">
  <title>Avis - Concert de jazz - MonEvent</title>
  <link rel="stylesheet" href="style.css">
  <style>
    .reviews-page {
      width: min(760px, calc(100% - 32px));
      margin: 48px auto;
    }
    .review-panel,
    .review-card {
      margin-bottom: 20px;
      padding: 24px;
      border: 1px solid #e3e7df;
      border-radius: 12px;
      background: #fff;
    }
    .review-panel label {
      display: block;
      margin-top: 16px;
      font-weight: 600;
    }
    .review-panel input,
    .review-panel select,
    .review-panel textarea {
      display: block;
      width: 100%;
      margin-top: 5px;
      padding: 10px;
      border: 1px solid #888;
      border-radius: 6px;
      font: inherit;
    }
    .review-panel textarea {
      min-height: 140px;
      resize: vertical;
    }
    .review-panel button {
      margin-top: 20px;
      padding: 10px 16px;
      border: 1px solid #070707;
      border-radius: 3px;
      color: #fff;
      background: #070707;
      cursor: pointer;
      font: inherit;
    }
    .review-message {
      padding: 12px 16px;
      border: 1px solid #b42318;
      border-radius: 6px;
      background: #fff;
      color: #8f1d14;
    }
    .review-message.success {
      border-color: #16803c;
      color: #12632f;
    }
    .review-meta {
      margin-bottom: 8px;
      color: #444;
    }
    .review-card p:last-child {
      margin-bottom: 0;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    .back-link {
      display: inline-block;
      margin: 8px 0 24px;
    }
  </style>
</head>
<body style="--site-background-image: url('image/fond.png')">
  <header class="site-header">
    <div class="container header-inner">
      <a class="brand" href="index.html#accueil" aria-label="MonEvent, accueil">
        <img src="image/instagram.png" alt="Logo Instagram">
        <span>MonEvent</span>
      </a>
      <nav class="navigation" aria-label="Navigation principale">
        <a href="index.html">Accueil</a>
        <a href="Evenements.html">Événements</a>
      </nav>
    </div>
  </header>
  <main class="reviews-page" id="avis">
    <p class="eyebrow">Votre expérience compte</p>
    <h1>Avis sur le concert de jazz</h1>
    <p>Partagez votre expérience et consultez les derniers avis laissés sur cet événement.</p>

    <?php if ($message !== ""): ?>
      <p class="review-message <?= escapeHtml($messageType) ?>" role="status"><?= escapeHtml($message) ?></p>
    <?php endif; ?>

    <section class="review-panel" aria-labelledby="review-form-title">
      <h2 id="review-form-title">Laisser un avis</h2>
      <form method="post" action="avis.php#avis">
        <input type="hidden" name="csrf_token" value="<?= escapeHtml($_SESSION["csrf_token"]) ?>">
        <label for="reviewer-name">Votre nom</label>
        <input id="reviewer-name" name="reviewer_name" maxlength="100" autocomplete="name" required value="<?= escapeHtml($reviewerName) ?>">

        <label for="rating">Votre note</label>
        <select id="rating" name="rating" required>
          <option value="">Choisir une note</option>
          <?php for ($score = 5; $score >= 1; $score--): ?>
            <option value="<?= $score ?>" <?= (string) $rating === (string) $score ? "selected" : "" ?>>
              <?= $score ?> / 5
            </option>
          <?php endfor; ?>
        </select>

        <label for="review-comment">Votre commentaire</label>
        <textarea id="review-comment" name="comment" maxlength="2000" required><?= escapeHtml($comment) ?></textarea>

        <button type="submit">Enregistrer mon avis</button>
      </form>
    </section>

    <section aria-labelledby="reviews-title">
      <h2 id="reviews-title">Derniers avis</h2>
      <?php if (!$databaseError && count($reviews) === 0): ?>
        <p>Aucun avis pour le moment. Soyez le premier à partager votre expérience !</p>
      <?php endif; ?>
      <?php foreach ($reviews as $review): ?>
        <article class="review-card">
          <h3><?= escapeHtml($review["nom"]) ?> — <?= (int) $review["note"] ?>/5</h3>
          <p class="review-meta">
            <?= escapeHtml(date("d/m/Y à H:i", strtotime($review["date_creation"]))) ?>
          </p>
          <p><?= escapeHtml($review["commentaire"]) ?></p>
        </article>
      <?php endforeach; ?>
    </section>

    <a class="back-link" href="evenement/Concert-de-jazz.html">Retour au concert de jazz</a>
  </main>
  <footer class="site-footer">
    <div class="container footer-inner"><p>© <span id="annee"></span> MonEvent</p></div>
  </footer>
  <script>document.getElementById("annee").textContent = new Date().getFullYear();</script>
</body>
</html>
