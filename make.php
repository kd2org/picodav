<?php

$out = fopen('index.php', 'w');

function clean_php_source(string $file): string
{
	$php = file_get_contents($file);
	$php = preg_replace('/^namespace\s+.*;\s*$/m', '', $php);
	$php = preg_replace('/<\?php\s*/', '', $php);
	$php = preg_replace(';/\*(?!\*/).*?\*/;s', '', $php);
	$php = preg_replace('/^/m', "\t", $php);
	$php = preg_replace('/^\s*$/m', "", $php);
	return $php;
}

$php = file_get_contents('server.php');
$php = strtr($php, [
	'//__KD2\WebDAV\Server__' => clean_php_source('lib/KD2/WebDAV/Server.php'),
	'//__KD2\WebDAV\AbstractStorage__' => clean_php_source('lib/KD2/WebDAV/AbstractStorage.php'),
	'/*__HTACCESS__*/' => var_export(file_get_contents('.htaccess'), true),
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
