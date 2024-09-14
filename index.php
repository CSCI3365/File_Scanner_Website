<?php
// This line needs to be run in your terminal 'composer require guzzlehttp/guzzle'
// Or you need to install the guzzle package manager to handle http requests.
require_once('vendor/autoload.php');
$client = new \GuzzleHttp\Client();
$a = getenv('VT_API2');
if (! $a) {
    throw new Exception('No API key found');
}

function getFile($client, $a) {
    $test_file_hash = "e19c1283c925b3206685ff522acfe3e6"; //test file_id for proof of concept
    $response = $client->request('GET', 'https://www.virustotal.com/api/v3/files/' . $test_file_hash, [
        'headers' => [
            'accept' => 'application/json',
            'x-apikey' => $a,
        ],
    ]);
    $return = json_decode($response->getBody(), true);
    echo $response->getBody();
}

function postFile() {
    $vt_URL_For_Files = 'https://www.virustotal.com/api/v3/files/';
    $response = $client->request('POST', $vt_URL_For_Files, [
        'multipart' => [
            'name' => 'file',
            'filename' => basename(path: $file),
            'contents' => file_get_contents(filename: $file),//updating this part to read from a stream 'data:application/octet-stream;name=' . $filename . ';base64,' . $base64_encoded_filecontents,
            'headers' => [
                'Content-Type' => 'application/pdf'
            ]
        ],
        'headers' => [
            'accept' => 'application/json',
            'x-apikey' => $a,
        ],
    ]);
    $results = json_decode($response->getBody(), true);
    saveScanResult($results);
    return $results;

}

// determine file status according to all results
function getAggregateResult($results) {
    $stats = $results['data']['attributes']['stats'];
    if ($stats['malicious'] > 0) return "malicious";
    if ($stats['suspicious'] > 0) return "suspicious";
    if ($stats['confirmed-timeout'] > 0 || $stats['timeout'] > 0 || $stats['failure'] > 0) return "failed";
    return "harmless";
}

// save uploaded file and send to VirusTotal
$scanResult = null;
$error = null;
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_FILES["fileToUpload"])) {
    echo "File recieved, saving and sending to VirusTotal";
    $target_dir = "uploads/";
    $target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);

    $target_file = $_FILES["fileToUpload"]["tmp_name"];
    if (!file_exists($target_file)) {
        $error = "File not found.";
        echo $error;
    } else {

    //if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
        $scanResult = getFile($client, $a);
    } //else {
        // $error = "Sorry, there was an error uploading your file.";
    //}
}

// save scan result to CSV
function saveScanResult($result) {
    $file = fopen("scan_results.csv", "a");

    $date = date("Y-m-d H:i:s", $result['data']['attributes']['date']);
    $fileId = $result['data']['id'];
    $aggregate_result = getAggregateResult($result['data']['attributes']['stats']);

    $write = [$date, $fileId, $aggregate_result];
    fputcsv($file, $write);

    fclose($file);
}

if ($scanResult) {
    saveScanResult($scanResult);
}

// get recent scans
function getRecentScans() {
    $recentResults = [];
    //FIXME: load file results to be displayed to user from scan_results.csv
    $file = fopen("scan_results.csv", "r");
    return [];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Virus Scan Website</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2 {
            color: #2c3e50;
        }
        form {
            margin-bottom: 20px;
        }
        input[type="file"] {
            margin-bottom: 10px;
        }
        input[type="submit"] {
            background-color: #3498db;
            color: white;
            padding: 10px 15px;
            border: none;
            cursor: pointer;
        }
        input[type="submit"]:hover {
            background-color: #2980b9;
        }
        .result-item {
            margin-bottom: 10px;
            padding: 10px;
            background-color: #f9f9f9;
            border-radius: 5px;
        }
        .error {
            color: red;
        }
    </style>
</head>
<body>
    <h1>Virus Scan Website</h1>

    <form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post" enctype="multipart/form-data">
        Select file to upload:
        <input type="file" name="fileToUpload" id="fileToUpload">
        <input type="submit" value="Upload and Scan" name="submit">
    </form>
    <!--
    <form action="<php echo $_SERVER['PHP_SELF']; ?>" method="get" enctype="multipart/form-data">
        See Scan Results
        <input type="submit" value="results" name="submit">
    </form> -->

    <?php if ($error): ?>
        <p class="error"><?php echo $error; ?></p>
    <?php endif; ?>
</body>
</html>
    <?php if ($scanResult): ?>
        <h2>Scan Results</h2>
        <p>File:  FIXME show file name and path</p>
        <p>For File: <?php #echo $_FILES["fileToUpload"]["name"]; ?></p>
        <p>Aggregate Result: <strong><?php #echo getAggregateResult($scanResult); ?></strong></p>
        <h3>Detailed Results:</h3>
        <?php foreach ($scanResult['data']['attributes']['results'] as $engine => $result): ?>
            <div class="result-item">
                <strong><?php echo $engine; ?>:</strong> <?php echo $result['category']; ?>
                <?php if ($result['result']): ?>
                    (<?php echo $result['result']; ?>)
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    <?php endif; ?>

    <h2>Recent Scans</h2>
    <?php $recentScans = getRecentScans(); ?>
    <?php if ($recentScans === []): ?>
        <p>No recent scans.</p>
    <?php else: ?>
        <ul>
            <?php foreach ($recentScans as $scan): ?>
                <li><?php echo $scan['fileName']; ?> - <?php echo $scan['result']; ?></li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>

</body>
</html>
