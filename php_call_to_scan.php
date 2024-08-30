<!-- php_call_to_scan.php -->
 <?php

require_once('vendor/autoload.php');

$client = new \GuzzleHttp\Client();
$a = getenv('VT_API2')

$response = $client->request('POST', 'https://www.virustotal.com/api/v3/this is where the filename will go', [
  'headers' => [
    'accept' => 'application/json',
    'content-type' => 'multipart/form-data',
    'x-apikey' => $a,
  ],
]);

echo $response->getBody();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
