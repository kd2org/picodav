<?php

namespace KD2\WebDAV
{
	//__KD2\WebDAV\Server__

	//__KD2\WebDAV\AbstractStorage__
}

namespace PicoDAV
{
	use KD2\WebDAV\AbstractStorage;
	use KD2\WebDAV\Exception as WebDAV_Exception;

	class Storage extends AbstractStorage
	{
		/**
		 * These file names will be ignored when doing a PUT
		 * as they are garbage, coming from some OS
		 */
		const PUT_IGNORE_PATTERN = '!^~(?:lock\.|^\._)|^(?:\.DS_Store|Thumbs\.db|desktop\.ini)$!';

		protected string $path;

		public function __construct()
		{
			$this->path = __DIR__ . '/';
		}

		static protected function glob(string $path, string $pattern = '', int $flags = 0): array
		{
			$path = preg_replace('/[\*\?\[\]]/', '\\\\$0', $path);
			return glob($path . $pattern, $flags);
		}

		public function list(string $uri, ?array $properties): iterable
		{
			$dirs = self::glob($this->path . $uri, '/*', \GLOB_ONLYDIR);
			$dirs = array_map('basename', $dirs);
			natcasesort($dirs);

			$files = self::glob($this->path . $uri, '/*');
			$files = array_map('basename', $files);
			$files = array_diff($files, $dirs);

			// Remove PHP files from listings
			$files = array_filter($files, fn($a) => !preg_match('/\.(?:php\d?|phtml|phps)$|^\./i', $a));

			if (!$uri) {
				$files = array_diff($files, ['webdav.js', 'webdav.css']);
			}

			natcasesort($files);

			$files = array_flip(array_merge($dirs, $files));
			$files = array_map(fn($a) => null, $files);
			return $files;
		}

		public function get(string $uri): ?array
		{
			if (substr(basename($uri), 0, 1) == '.') {
				throw new WebDAV_Exception('Invalid filename', 403);
			}

			$path = $this->path . $uri;

			if (!file_exists($path)) {
				return null;
			}

			return ['path' => $path];
		}

		public function exists(string $uri): bool
		{
			return file_exists($this->path . $uri);
		}

		public function get_file_property(string $uri, string $name, int $depth)
		{
			$target = $this->path . $uri;

			switch ($name) {
				case 'DAV::getcontentlength':
					return is_dir($target) ? null : filesize($target);
				case 'DAV::getcontenttype':
					// ownCloud app crashes if mimetype is provided for a directory
					// https://github.com/owncloud/android/issues/3768
					return is_dir($target) ? null : mime_content_type($target);
				case 'DAV::resourcetype':
					return is_dir($target) ? 'collection' : '';
				case 'DAV::getlastmodified':
					if (!$uri && $depth == 0 && is_dir($target)) {
						$mtime = self::getDirectoryMTime($target);
					}
					else {
						$mtime = filemtime($target);
					}

					if (!$mtime) {
						return null;
					}

					return new \DateTime('@' . $mtime);
				case 'DAV::displayname':
					return basename($target);
				case 'DAV::ishidden':
					return basename($target)[0] == '.';
				case 'DAV::getetag':
					$hash = filemtime($target) . filesize($target);
					return md5($hash . $target);
				case 'DAV::lastaccessed':
					return new \DateTime('@' . fileatime($target));
				case 'DAV::creationdate':
					return new \DateTime('@' . filectime($target));
				case 'http://owncloud.org/ns:permissions':
					$permissions = 'G';

					if (is_writeable($target) && !FORCE_READONLY) {
						$permissions .= 'DNVWCK';
					}

					return $permissions;
				case WebDAV::PROP_DIGEST_MD5:
					if (!is_file($target)) {
						return null;
					}

					return md5_file($target);
				default:
					break;
			}

			return null;
		}

		public function properties(string $uri, ?array $properties, int $depth): ?array
		{
			$target = $this->path . $uri;

			if (!file_exists($target)) {
				return null;
			}

			if (null === $properties) {
				$properties = WebDAV::BASIC_PROPERTIES;
			}

			$out = [];

			foreach ($properties as $name) {
				$v = $this->get_file_property($uri, $name, $depth);

				if (null !== $v) {
					$out[$name] = $v;
				}
			}

			return $out;
		}

		public function put(string $uri, $pointer, ?string $hash, ?int $mtime): bool
		{
			if (preg_match(self::PUT_IGNORE_PATTERN, basename($uri))) {
				return false;
			}

			if (FORCE_READONLY) {
				throw new WebDAV_Exception('Write access is disabled', 403);
			}

			if (substr(basename($uri), 0, 1) == '.') {
				throw new WebDAV_Exception('Invalid filename', 403);
			}

			$target = $this->path . $uri;
			$parent = dirname($target);

			if (is_dir($target)) {
				throw new WebDAV_Exception('Target is a directory', 409);
			}

			if (!file_exists($parent)) {
				mkdir($parent, 0770, true);
			}

			$new = !file_exists($target);
			$delete = false;
			$size = 0;
			$quota = disk_free_space($this->path);

			$tmp_file = '.tmp.' . sha1($target);
			$out = fopen($tmp_file, 'w');

			while (!feof($pointer)) {
				$bytes = fread($pointer, 8192);
				$size += strlen($bytes);

				if ($size > $quota) {
					$delete = true;
					break;
				}

				fwrite($out, $bytes);
			}

			fclose($out);
			fclose($pointer);

			if ($delete) {
				@unlink($tmp_file);
				throw new WebDAV_Exception('Your quota is exhausted', 403);
			}
			elseif ($hash && md5_file($tmp_file) != $hash) {
				@unlink($tmp_file);
				throw new WebDAV_Exception('The data sent does not match the supplied MD5 hash', 400);
			}
			else {
				rename($tmp_file, $target);
			}

			if ($mtime) {
				@touch($target, $mtime);
			}

			return $new;
		}

		public function delete(string $uri): void
		{
			if (FORCE_READONLY) {
				throw new WebDAV_Exception('Write access is disabled', 403);
			}

			if (substr(basename($uri), 0, 1) == '.') {
				throw new WebDAV_Exception('Invalid filename', 403);
			}

			$target = $this->path . $uri;

			if (!file_exists($target)) {
				throw new WebDAV_Exception('Target does not exist', 404);
			}

			if (!is_writeable($target)) {
				throw new WebDAV_Exception('File permissions says that you cannot delete this, sorry.', 403);
			}

			if (is_dir($target)) {
				foreach (self::glob($target, '/*') as $file) {
					$this->delete(substr($file, strlen($this->path)));
				}

				rmdir($target);
			}
			else {
				unlink($target);
			}
		}

		public function copymove(bool $move, string $uri, string $destination): bool
		{
			if (FORCE_READONLY) {
				throw new WebDAV_Exception('Write access is disabled', 403);
			}

			if (substr(basename($uri), 0, 1) == '.') {
				throw new WebDAV_Exception('Invalid filename', 403);
			}

			if (substr(basename($destination), 0, 1) == '.') {
				throw new WebDAV_Exception('Invalid filename', 403);
			}

			$source = $this->path . $uri;
			$target = $this->path . $destination;
			$parent = dirname($target);

			if (!file_exists($source)) {
				throw new WebDAV_Exception('File not found', 404);
			}

			$overwritten = file_exists($target);

			if (!is_dir($parent)) {
				throw new WebDAV_Exception('Target parent directory does not exist', 409);
			}

			if (false === $move) {
				$quota = disk_free_space($this->path);

				if (filesize($source) > $quota) {
					throw new WebDAV_Exception('Your quota is exhausted', 403);
				}
			}

			if ($overwritten) {
				$this->delete($destination);
			}

			$method = $move ? 'rename' : 'copy';

			if ($method == 'copy' && is_dir($source)) {
				@mkdir($target, 0770, true);

				foreach ($iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($source), \RecursiveIteratorIterator::SELF_FIRST) as $item)
				{
					if ($item->isDir()) {
						@mkdir($target . DIRECTORY_SEPARATOR . $iterator->getSubPathname());
					} else {
						copy($item, $target . DIRECTORY_SEPARATOR . $iterator->getSubPathname());
					}
				}
			}
			else {
				$method($source, $target);

				$this->getResourceProperties($uri)->move($destination);
			}

			return $overwritten;
		}

		public function copy(string $uri, string $destination): bool
		{
			return $this->copymove(false, $uri, $destination);
		}

		public function move(string $uri, string $destination): bool
		{
			return $this->copymove(true, $uri, $destination);
		}

		public function mkcol(string $uri): void
		{
			if (FORCE_READONLY) {
				throw new WebDAV_Exception('Write access is disabled', 403);
			}

			if (substr(basename($uri), 0, 1) == '.') {
				throw new WebDAV_Exception('Invalid filename', 403);
			}

			if (!disk_free_space($this->path)) {
				throw new WebDAV_Exception('Your quota is exhausted', 403);
			}

			$target = $this->path . $uri;
			$parent = dirname($target);

			if (file_exists($target)) {
				throw new WebDAV_Exception('There is already a file with that name', 405);
			}

			if (!file_exists($parent)) {
				throw new WebDAV_Exception('The parent directory does not exist', 409);
			}

			mkdir($target, 0770);
		}

		static public function getDirectoryMTime(string $path): int
		{
			$last = 0;
			$path = rtrim($path, '/');

			foreach (self::glob($path, '/*', GLOB_NOSORT) as $f) {
				if (is_dir($f)) {
					$m = self::getDirectoryMTime($f);

					if ($m > $last) {
						$last = $m;
					}
				}

				$m = filemtime($f);

				if ($m > $last) {
					$last = $m;
				}
			}

			return $last;
		}
	}

	class Server extends \KD2\WebDAV\Server
	{
		protected function html_directory(string $uri, iterable $list): ?string
		{
			$out = parent::html_directory($uri, $list);

			if (null !== $out) {
				$out = str_replace('<body>', sprintf('<body style="opacity: 0"><script type="text/javascript" src="%s/webdav.js"></script>', rtrim($this->base_uri, '/')), $out);
			}

			return $out;
		}
	}
}

namespace {
	use PicoDAV\Server;
	use PicoDAV\Storage;

	$uri = strtok($_SERVER['REQUEST_URI'], '?');
	$root = substr(__DIR__, strlen($_SERVER['DOCUMENT_ROOT']));

	if (false !== strpos($uri, '..')) {
		http_response_code(404);
		die('Invalid URL');
	}

	$relative_uri = ltrim(substr($uri, strlen($root)), '/');

	const DEFAULT_CONFIG = [
		'FORCE_READONLY' => false,
	];

	$config = [];

	if (file_exists(__DIR__ . '/.picodav.ini')) {
		$config = parse_ini_file(__DIR__ . '/.picodav.ini');
		$config = array_change_key_case($config, \CASE_UPPER);
	}

	foreach (DEFAULT_CONFIG as $key => $value) {
		if (array_key_exists($key, $config)) {
			$value = $config[$key];
		}

		if (is_bool(DEFAULT_CONFIG[$key])) {
			$value = boolval($value);
		}

		define('PicoDAV\\' . $key, $value);
	}

	if ($relative_uri == 'webdav.js' || $relative_uri == 'webdav.css') {
		http_response_code(200);

		if ($relative_uri == 'webdav.js') {
			header('Content-Type: text/javascript', true);
		}
		else {
			header('Content-Type: text/css', true);
		}

		$seconds_to_cache = 3600 * 24 * 365;
		$ts = gmdate("D, d M Y H:i:s", time() + $seconds_to_cache) . " GMT";
		header("Expires: " . $ts);
		header("Pragma: cache");
		header("Cache-Control: max-age=" . $seconds_to_cache);

		$fp = fopen(__FILE__, 'r');

		if ($relative_uri == 'webdav.js') {
			fseek($fp, __PHP_SIZE__, SEEK_SET);
			echo fread($fp, __JS_SIZE__);
		}
		else {
			fseek($fp, __PHP_SIZE__ + __JS_SIZE__, SEEK_SET);
			echo fread($fp, __CSS_SIZE__);
		}

		fclose($fp);

		exit;
	}

	$dav = new Server;
	$dav->setStorage(new Storage);

	$dav->setBaseURI($root);

	if (!$dav->route($uri)) {
		http_response_code(404);
		die('Invalid URL, sorry');
	}

	exit;
}
