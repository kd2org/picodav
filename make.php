<?php

$out = fopen('index.php', 'w');

$php = file_get_contents('server.php');
$php = strtr($php, [
	'__JS_SIZE__' => filesize('webdav.js'),
	'__CSS_SIZE__' => filesize('webdav.css'),
]);

$php = preg_replace('/\}\s*$/', "\n?>\n", $php);
$end = "\n\n<?php } ?>\n";

$size = strlen($php);
$count = substr_count($php, '__PHP_SIZE__');
$size -= strlen('__PHP_SIZE__') * $count;
$size += strlen((string) $size) * $count;

$php = str_replace('__PHP_SIZE__', $size, $php);

fwrite($out, $php);
fwrite($out, file_get_contents('webdav.js'));
fwrite($out, file_get_contents('webdav.css'));
fwrite($out, $end);
fclose($out);
