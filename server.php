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
		protected ?string $user = null;

		public array $users = [];

		public function __construct(string $path)
		{
			$this->path = $path . '/';
		}

		public function auth(): bool
		{
			if (ANONYMOUS_WRITE && ANONYMOUS_READ) {
				return true;
			}

			if ($this->user) {
				return true;
			}

			$user = $_SERVER['PHP_AUTH_USER'] ?? null;
			$password = $_SERVER['PHP_AUTH_PW'] ?? null;

			if (!array_key_exists($user, $this->users)) {
				return false;
			}

			$hash = $this->users[$user]['password'] ?? null;

			// If no password is set, we accept any password as we consider that a .htaccess/.htpasswd
			// access has been granted
			if (null !== $hash && !password_verify($password, $hash)) {
				return false;
			}

			$this->user = $user;
			return true;
		}

		static protected function glob(string $path, string $pattern = '', int $flags = 0): array
		{
			$path = preg_replace('/[\*\?\[\]]/', '\\\\$0', $path);
			return glob($path . $pattern, $flags);
		}

		public function canRead(string $uri): bool
		{
			if (in_array($uri, INTERNAL_FILES)) {
				return false;
			}

			if (preg_match('/\.(?:php\d?|phtml|phps)$|^\./i', $uri)) {
				return false;
			}

			if (ANONYMOUS_READ) {
				return true;
			}

			if (!$this->auth()) {
				return false;
			}

			$restrict = $this->users[$this->user]['restrict'] ?? [];

			if (!is_array($restrict) || empty($restrict)) {
				return true;
			}

			foreach ($restrict as $match) {
				if (0 === strpos($uri, $match)) {
					return true;
				}
			}

			return false;
		}

		public function canWrite(string $uri): bool
		{
			if (!$this->auth() && !ANONYMOUS_WRITE) {
				return false;
			}

			if (!$this->canRead($uri)) {
				return false;
			}

			if (ANONYMOUS_WRITE) {
				return true;
			}

			if (!$this->auth() || empty($this->users[$this->user]['write'])) {
				return false;
			}

			$restrict = $this->users[$this->user]['restrict_write'] ?? [];

			if (!is_array($restrict) || empty($restrict)) {
				return true;
			}

			foreach ($restrict as $match) {
				if (0 === strpos($uri, $match)) {
					return true;
				}
			}

			return false;
		}

		public function canOnlyCreate(string $uri): bool
		{
			$restrict = $this->users[$this->user]['restrict_write'] ?? [];

			if (in_array($uri, $restrict, true)) {
				return true;
			}

			$restrict = $this->users[$this->user]['restrict'] ?? [];

			if (in_array($uri, $restrict, true)) {
				return true;
			}

			return false;
		}

		public function list(string $uri, ?array $properties): iterable
		{
			if (!$this->canRead($uri . '/')) {
				//throw new WebDAV_Exception('Access forbidden', 403);
			}

			$dirs = self::glob($this->path . $uri, '/*', \GLOB_ONLYDIR);
			$dirs = array_map('basename', $dirs);
			$dirs = array_filter($dirs, fn($a) => $this->canRead(ltrim($uri . '/' . $a, '/') . '/'));
			natcasesort($dirs);

			$files = self::glob($this->path . $uri, '/*');
			$files = array_map('basename', $files);
			$files = array_diff($files, $dirs);

			// Remove PHP files and dot-files from listings
			$files = array_filter($files, fn($a) => $this->canRead(ltrim($uri . '/' . $a, '/')));

			natcasesort($files);

			$files = array_flip(array_merge($dirs, $files));
			$files = array_map(fn($a) => null, $files);

			return $files;
		}

		public function get(string $uri): ?array
		{
			if (!$this->canRead($uri)) {
				throw new WebDAV_Exception('Access forbidden', 403);
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
				case 'DAV::displayname':
					return basename($uri);
				case 'DAV::getcontentlength':
					return is_dir($target) ? null : filesize($target);
				case 'DAV::getcontenttype':
					// ownCloud app crashes if mimetype is provided for a directory
					// https://github.com/owncloud/android/issues/3768
					return is_dir($target) ? null : mime_content_type($target);
				case 'DAV::resourcetype':
					return is_dir($target) ? 'collection' : '';
				case 'DAV::getlastmodified':
					$mtime = filemtime($target);

					if (!$mtime) {
						return null;
					}

					return new \DateTime('@' . $mtime);
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

					if (is_dir($target)) {
						$uri .= '/';
					}

					if (is_writeable($target) && $this->canWrite($uri)) {
						// If the directory is one of the restricted paths,
						// then we can only do stuff INSIDE, and not delete/rename the directory itself
						if ($this->canOnlyCreate($uri)) {
							$permissions .= 'CK';
						}
						else {
							$permissions .= 'DNVWCK';
						}
					}

					return $permissions;
				case Server::PROP_DIGEST_MD5:
					if (!is_file($target) || is_dir($target) || !is_readable($target)) {
						return null;
					}

					return md5_file($target);
				default:
					break;
			}

			return null;
		}

		public function propfind(string $uri, ?array $properties, int $depth): ?array
		{
			$target = $this->path . $uri;

			if (!file_exists($target)) {
				return null;
			}

			if (null === $properties) {
				$properties = Server::BASIC_PROPERTIES;
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

		public function put(string $uri, $pointer, ?string $hash_algo, ?string $hash): bool
		{
			if (preg_match(self::PUT_IGNORE_PATTERN, basename($uri))) {
				return false;
			}

			if (!$this->canWrite($uri)) {
				throw new WebDAV_Exception('Access forbidden', 403);
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

			$tmp_file = $this->path . '.tmp.' . sha1($target);
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
				throw new WebDAV_Exception('Your quota is exhausted', 507);
			}
			elseif ($hash && $hash_algo == 'MD5' && md5_file($tmp_file) != $hash) {
				@unlink($tmp_file);
				throw new WebDAV_Exception('The data sent does not match the supplied MD5 hash', 400);
			}
			elseif ($hash && $hash_algo == 'SHA1' && sha1_file($tmp_file) != $hash) {
				@unlink($tmp_file);
				throw new WebDAV_Exception('The data sent does not match the supplied SHA1 hash', 400);
			}
			else {
				rename($tmp_file, $target);
			}

			return $new;
		}

		public function delete(string $uri): void
		{
			if (!$this->canWrite($uri)) {
				throw new WebDAV_Exception('Access forbidden', 403);
			}

			if ($this->canOnlyCreate($uri)) {
				throw new WebDAV_Exception('Access forbidden', 403);
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
			if (!$this->canWrite($uri)
				|| !$this->canWrite($destination)
				|| $this->canOnlyCreate($uri)) {
				throw new WebDAV_Exception('Access forbidden', 403);
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
					throw new WebDAV_Exception('Your quota is exhausted', 507);
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
			if (!$this->canWrite($uri)) {
				throw new WebDAV_Exception('Access forbidden', 403);
			}

			if (!disk_free_space($this->path)) {
				throw new WebDAV_Exception('Your quota is exhausted', 507);
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

		public function touch(string $uri, \DateTimeInterface $datetime): bool
		{
			$target = $this->path . $uri;
			return @touch($target, $datetime->getTimestamp());
		}
	}

	class Server extends \KD2\WebDAV\Server
	{
		protected function html_directory(string $uri, iterable $list): ?string
		{
			$out = parent::html_directory($uri, $list);

			if (null !== $out) {
				$out = str_replace('<body>', sprintf('<body style="opacity: 0"><script type="text/javascript" src="%s/.webdav/webdav.js"></script>', rtrim($this->base_uri, '/')), $out);
			}

			return $out;
		}

		public function route(?string $uri = null): bool
		{
			if (!ANONYMOUS_WRITE && !ANONYMOUS_READ && !$this->storage->auth()) {
				$this->requireAuth();
				return true;
			}

			return parent::route($uri);
		}

		protected function requireAuth(): void
		{
			http_response_code(401);
			header('WWW-Authenticate: Basic realm="Please login"');
			echo '<h2>Error 401</h2><h1>You need to login to access this.</h1>';
		}

		public function error(WebDAV_Exception $e)
		{
			if ($e->getCode() == 403 && !$this->storage->auth() && count($this->storage->users)) {
				return;
			}

			parent::error($e);
		}

		protected string $_log = '';

		public function log(string $message, ...$params): void
		{
			if (!HTTP_LOG_FILE) {
				return;
			}

			$this->_log .= vsprintf($message, $params) . "\n";
		}

		public function __destruct()
		{
			if (!$this->_log) {
				return;
			}

			file_put_contents(HTTP_LOG_FILE, $this->_log, \FILE_APPEND);
		}
	}
}

namespace {
	use PicoDAV\Server;
	use PicoDAV\Storage;

	$uri = strtok($_SERVER['REQUEST_URI'], '?');
	$self = $_SERVER['SCRIPT_FILENAME'];
	$self_dir = dirname($self);
	$root = substr(dirname($_SERVER['SCRIPT_FILENAME']), strlen($_SERVER['DOCUMENT_ROOT']));
	$root = '/' . ltrim($root, '/');

	if (false !== strpos($uri, '..')) {
		http_response_code(404);
		die('Invalid URL');
	}

	$relative_uri = ltrim(substr($uri, strlen($root)), '/');

	if (!empty($_SERVER['SERVER_SOFTWARE']) && stristr($_SERVER['SERVER_SOFTWARE'], 'apache') && !file_exists($self_dir . '/.htaccess')) {
		file_put_contents($self_dir . '/.htaccess', str_replace('index.php', basename($self), /*__HTACCESS__*/));
	}

	if ($relative_uri == '.webdav/webdav.js' || $relative_uri == '.webdav/webdav.css') {
		http_response_code(200);

		if ($relative_uri == '.webdav/webdav.js') {
			header('Content-Type: text/javascript', true);
		}
		else {
			header('Content-Type: text/css', true);
		}

		$seconds_to_cache = 3600 * 24 * 5;
		$ts = gmdate("D, d M Y H:i:s", time() + $seconds_to_cache) . " GMT";
		header("Expires: " . $ts);
		header("Pragma: cache");
		header("Cache-Control: max-age=" . $seconds_to_cache);

		$fp = fopen(__FILE__, 'r');

		if ($relative_uri == '.webdav/webdav.js') {
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

	$config_file = $self_dir . '/.picodav.ini';
	define('PicoDAV\INTERNAL_FILES', ['.picodav.ini', $self_dir, '.webdav/webdav.js', '.webdav/webdav.css']);

	const DEFAULT_CONFIG = [
		'ANONYMOUS_READ' => true,
		'ANONYMOUS_WRITE' => false,
		'HTTP_LOG_FILE' => null,
	];

	$config = [];
	$storage = new Storage($self_dir);

	if (file_exists($config_file)) {
		$config = parse_ini_file($config_file, true);
		$users = array_filter($config, 'is_array');
		$config = array_diff_key($config, $users);
		$config = array_change_key_case($config, \CASE_UPPER);
		$replace = [];

		// Encrypt plaintext passwords
		foreach ($users as $name => $properties) {
			if (isset($properties['password']) && substr($properties['password'], 0, 1) != '$') {
				$users[$name]['password'] = $replace[$name] = password_hash($properties['password'], null);
			}
		}

		if (count($replace)) {
			$lines = file($config_file);
			$current = null;

			foreach ($lines as &$line) {
				if (preg_match('/^\s*\[(\w+)\]\s*$/', $line, $match)) {
					$current = $match[1];
					continue;
				}

				if ($current && isset($replace[$current]) && preg_match('/^\s*password\s*=/', $line)) {
					$line = sprintf("password = %s\n", var_export($replace[$current], true));
				}
			}

			unset($line, $current);

			file_put_contents($config_file, implode('', $lines));
		}

		$storage->users = $users;
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


	$dav = new Server();
	$dav->setStorage($storage);

	$dav->setBaseURI($root);

	if (!$dav->route($uri)) {
		http_response_code(404);
		die('Unknown URL, sorry.');
	}

	exit;
}
