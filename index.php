<?php

namespace KD2\WebDAV
{
	
	class Exception extends \RuntimeException {}

	class Server
	{
		// List of basic DAV properties that you should return if $requested_properties is NULL
		const BASIC_PROPERTIES = [
			'DAV::resourcetype', // should be empty for files, and 'collection' for directories
			'DAV::getcontenttype', // MIME type
			'DAV::getlastmodified', // File modification date (must be \DateTimeInterface)
			'DAV::getcontentlength', // file size
			'DAV::displayname', // File name for display
		];

		const EXTENDED_PROPERTIES = [
			'DAV::getetag',
			'DAV::creationdate',
			'DAV::lastaccessed',
			'DAV::ishidden', // Microsoft thingy
			'DAV::quota-used-bytes',
			'DAV::quota-available-bytes',
		];

		const PROP_NAMESPACE_MICROSOFT = 'urn:schemas-microsoft-com:';

		const MODIFICATION_TIME_PROPERTIES = [
			'DAV::lastmodified',
			'DAV::creationdate',
			'DAV::getlastmodified',
			'urn:schemas-microsoft-com::Win32LastModifiedTime',
			'urn:schemas-microsoft-com::Win32CreationTime',
		];

		// Custom properties

		const PROP_DIGEST_MD5 = 'urn:karadav:digest_md5';

		const EMPTY_PROP_VALUE = 'DAV::empty';

		const SHARED_LOCK = 'shared';
		const EXCLUSIVE_LOCK = 'exclusive';

		protected bool $enable_gzip = true;

		protected string $base_uri;

		public string $original_uri;

		public string $prefix = '';

		protected AbstractStorage $storage;

		public function setStorage(AbstractStorage $storage)
		{
			$this->storage = $storage;
		}

		public function getStorage(): AbstractStorage
		{
			return $this->storage;
		}

		public function setBaseURI(string $uri): void
		{
			$this->base_uri = '/' . ltrim($uri, '/');
			$this->base_uri = rtrim($this->base_uri, '/') . '/';
		}

		protected function extendExecutionTime(): void
		{
			if (false === strpos(@ini_get('disable_functions'), 'set_time_limit')) {
				@set_time_limit(3600);
			}

			@ini_set('max_execution_time', '3600');
			@ini_set('max_input_time', '3600');
		}

		protected function _prefix(string $uri): string
		{
			if (!$this->prefix) {
				return $uri;
			}

			return rtrim(rtrim($this->prefix, '/') . '/' . ltrim($uri, '/'), '/');
		}

		protected function html_directory(string $uri, iterable $list): ?string
		{
			// Not a file: let's serve a directory listing if you are browsing with a web browser
			if (substr($this->original_uri, -1) != '/') {
				http_response_code(301);
				header(sprintf('Location: /%s/', trim($this->base_uri . $uri, '/')), true);
				return null;
			}

			$out = sprintf('<!DOCTYPE html><html data-webdav-url="%s"><head><meta name="viewport" content="width=device-width, initial-scale=1.0, target-densitydpi=device-dpi" /><style>
				body { font-size: 1.1em; font-family: Arial, Helvetica, sans-serif; }
				table { border-collapse: collapse; }
				th, td { padding: .5em; text-align: left; border: 2px solid #ccc; }
				span { font-size: 40px; line-height: 40px; }
				</style>', '/' . ltrim($this->base_uri, '/'));

			$out .= sprintf('<title>%s</title></head><body><h1>%1$s</h1><table>', htmlspecialchars($uri ? str_replace('/', ' / ', $uri) . ' - Files' : 'Files'));

			if (trim($uri)) {
				$out .= '<tr><th colspan=3><a href="../"><b>Back</b></a></th></tr>';
			}

			$props = null;

			foreach ($list as $file => $props) {
				if (null === $props) {
					$props = $this->storage->propfind(trim($uri . '/' . $file, '/'), self::BASIC_PROPERTIES, 0);
				}

				$collection = !empty($props['DAV::resourcetype']) && $props['DAV::resourcetype'] == 'collection';

				if ($collection) {
					$out .= sprintf('<tr><td>[DIR]</td><th><a href="%s/"><b>%s</b></a></th></tr>', rawurlencode($file), htmlspecialchars($file));
				}
				else {
					$size = $props['DAV::getcontentlength'];

					if ($size > 1024*1024) {
						$size = sprintf('%d MB', $size / 1024 / 1024);
					}
					elseif ($size) {
						$size = sprintf('%d KB', $size / 1024);
					}

					$date = $props['DAV::getlastmodified'];

					if ($date instanceof \DateTimeInterface) {
						$date = $date->format('d/m/Y H:i');
					}

					$out .= sprintf('<tr><td></td><th><a href="%s">%s</a></th><td>%s</td><td>%s</td></tr>',
						rawurlencode($file),
						htmlspecialchars($file),
						$size,
						$date
					);
				}
			}

			$out .= '</table>';

			if (null === $props) {
				$out .= '<p>This directory is empty.</p>';
			}

			$out .= '</body></html>';

			return $out;
		}

		public function http_delete(string $uri): ?string
		{
			// check RFC 2518 Section 9.2, last paragraph
			if (isset($_SERVER['HTTP_DEPTH']) && $_SERVER['HTTP_DEPTH'] != 'infinity') {
				throw new Exception('We can only delete to infinity', 400);
			}

			$uri = $this->_prefix($uri);

			$this->checkLock($uri);

			$this->storage->delete($uri);

			if ($token = $this->getLockToken()) {
				$this->storage->unlock($uri, $token);
			}

			http_response_code(204);
			header('Content-Length: 0', true);
			return null;
		}

		public function http_put(string $uri): ?string
		{
			if (!empty($_SERVER['HTTP_CONTENT_TYPE']) && !strncmp($_SERVER['HTTP_CONTENT_TYPE'], 'multipart/', 10)) {
				throw new Exception('Multipart PUT requests are not supported', 501);
			}

			if (!empty($_SERVER['HTTP_CONTENT_ENCODING'])) {
				if (false !== strpos($_SERVER['HTTP_CONTENT_ENCODING'], 'gzip')) {
					// Might be supported later?
					throw new Exception('Content Encoding is not supported', 501);
				}
				else {
					throw new Exception('Content Encoding is not supported', 501);
				}
			}

			if (!empty($_SERVER['HTTP_CONTENT_RANGE'])) {
				throw new Exception('Content Range is not supported', 501);
			}

			// See SabreDAV CorePlugin for reason why OS/X Finder is buggy
			if (isset($_SERVER['HTTP_X_EXPECTED_ENTITY_LENGTH'])) {
				throw new Exception('This server is not compatible with OS/X finder. Consider using a different WebDAV client or webserver.', 403);
			}

			$hash = null;
			$hash_algo = null;

			// Support for checksum matching
			// https://dcache.org/old/manuals/UserGuide-6.0/webdav.shtml#checksums
			if (!empty($_SERVER['HTTP_CONTENT_MD5'])) {
				$hash = bin2hex(base64_decode($_SERVER['HTTP_CONTENT_MD5']));
				$hash_algo = 'MD5';
			}
			// Support for ownCloud/NextCloud checksum
			// https://github.com/owncloud-archive/documentation/issues/2964
			elseif (!empty($_SERVER['HTTP_OC_CHECKSUM'])
				&& preg_match('/MD5:[a-f0-9]{32}|SHA1:[a-f0-9]{40}/', $_SERVER['HTTP_OC_CHECKSUM'], $match)) {
				$hash_algo = strtok($match[0], ':');
				$hash = strtok('');
			}

			$uri = $this->_prefix($uri);

			$this->checkLock($uri);

			if (!empty($_SERVER['HTTP_IF_MATCH'])) {
				$etag = trim($_SERVER['HTTP_IF_MATCH'], '" ');
				$prop = $this->storage->propfind($uri, ['DAV::getetag'], 0);

				if (!empty($prop['DAV::getetag']) && $prop['DAV::getetag'] != $etag) {
					throw new Exception('ETag did not match condition', 412);
				}
			}

			// Specific to NextCloud/ownCloud, to allow setting file mtime
			// This expects a UNIX timestamp
			$mtime = (int)($_SERVER['HTTP_X_OC_MTIME'] ?? 0) ?: null;

			$this->extendExecutionTime();

			$stream = fopen('php://input', 'r');

			// mod_fcgid <= 2.3.9 doesn't handle chunked transfer encoding for PUT requests
			// see https://github.com/kd2org/picodav/issues/6
			if (strstr($_SERVER['HTTP_TRANSFER_ENCODING'] ?? '', 'chunked') && PHP_SAPI == 'fpm-fcgi') {
				// We can't seek here
				// see https://github.com/php/php-src/issues/9441
				$l = strlen(fread($stream, 1));

				if ($l === 0) {
					throw new Exception('This server cannot accept "Transfer-Encoding: chunked" uploads (please upgrade to mod_fcgid >= 2.3.10).', 500);
				}

				// reset stream
				fseek($stream, 0, SEEK_SET);
			}

			$created = $this->storage->put($uri, $stream, $hash_algo, $hash);

			if ($mtime) {
				$mtime = new \DateTime('@' . $mtime);

				if ($this->storage->touch($uri, $mtime)) {
					header('X-OC-MTime: accepted');
				}
			}

			$prop = $this->storage->propfind($uri, ['DAV::getetag'], 0);

			if (!empty($prop['DAV::getetag'])) {
				$value = $prop['DAV::getetag'];

				if (substr($value, 0, 1) != '"') {
					$value = '"' . $value . '"';
				}

				header(sprintf('ETag: %s', $value));
			}

			http_response_code($created ? 201 : 204);
			return null;
		}

		public function http_head(string $uri, array &$props = []): ?string
		{
			$uri = $this->_prefix($uri);

			$requested_props = self::BASIC_PROPERTIES;
			$requested_props[] = 'DAV::getetag';

			// RFC 3230 https://www.rfc-editor.org/rfc/rfc3230.html
			if (!empty($_SERVER['HTTP_WANT_DIGEST'])) {
				$requested_props[] = self::PROP_DIGEST_MD5;
			}

			$props = $this->storage->propfind($uri, $requested_props, 0);

			if (!$props) {
				throw new Exception('Resource Not Found', 404);
			}

			http_response_code(200);

			if (isset($props['DAV::getlastmodified'])
				&& $props['DAV::getlastmodified'] instanceof \DateTimeInterface) {
				header(sprintf('Last-Modified: %s', $props['DAV::getlastmodified']->format(\DATE_RFC7231)));
			}

			if (!empty($props['DAV::getetag'])) {
				$value = $props['DAV::getetag'];

				if (substr($value, 0, 1) != '"') {
					$value = '"' . $value . '"';
				}

				header(sprintf('ETag: %s', $value));
			}

			if (empty($props['DAV::resourcetype']) || $props['DAV::resourcetype'] != 'collection') {
				if (!empty($props['DAV::getcontenttype'])) {
					header(sprintf('Content-Type: %s', $props['DAV::getcontenttype']));
				}

				if (!empty($props['DAV::getcontentlength'])) {
					header(sprintf('Content-Length: %d', $props['DAV::getcontentlength']));
					header('Accept-Ranges: bytes');
				}
			}

			if (!empty($props[self::PROP_DIGEST_MD5])) {
				header(sprintf('Digest: md5=%s', base64_encode(hex2bin($props[self::PROP_DIGEST_MD5]))));
			}

			return null;
		}

		public function http_get(string $uri): ?string
		{
			$props = [];
			$this->http_head($uri, $props);

			$uri = $this->_prefix($uri);

			$is_collection = !empty($props['DAV::resourcetype']) && $props['DAV::resourcetype'] == 'collection';
			$out = '';

			if ($is_collection) {
				$list = $this->storage->list($uri, self::BASIC_PROPERTIES);

				if (!isset($_SERVER['HTTP_ACCEPT']) || false === strpos($_SERVER['HTTP_ACCEPT'], 'html')) {
					$list = is_array($list) ? $list : iterator_to_array($list);

					if (!count($list)) {
						return "Nothing in this collection\n";
					}

					return implode("\n", array_keys($list));
				}

				header('Content-Type: text/html; charset=utf-8', true);

				return $this->html_directory($uri, $list);
			}

			$file = $this->storage->get($uri);

			if (!$file) {
				throw new Exception('File Not Found', 404);
			}

			// If the file was returned to the client by the storage backend, stop here
			if (!empty($file['stop'])) {
				return null;
			}

			if (!isset($file['content']) && !isset($file['resource']) && !isset($file['path'])) {
				throw new \RuntimeException('Invalid file array returned by ::get(): ' . print_r($file, true));
			}

			$this->extendExecutionTime();

			$length = $start = $end = null;
			$gzip = false;

			if (isset($_SERVER['HTTP_RANGE'])
				&& preg_match('/^bytes=(\d*)-(\d*)$/i', $_SERVER['HTTP_RANGE'], $match)
				&& $match[1] . $match[2] !== '') {
				$start = $match[1] === '' ? null : (int) $match[1];
				$end   = $match[2] === '' ? null : (int) $match[2];

				if (null !== $start && $start < 0) {
					throw new Exception('Start range cannot be satisfied', 416);
				}

				if (isset($props['DAV::getcontentlength']) && $start > $props['DAV::getcontentlength']) {
					throw new Exception('End range cannot be satisfied', 416);
				}

				$this->log('HTTP Range requested: %s-%s', $start, $end);
			}
			elseif ($this->enable_gzip
				&& isset($_SERVER['HTTP_ACCEPT_ENCODING'])
				&& false !== strpos($_SERVER['HTTP_ACCEPT_ENCODING'], 'gzip')
				&& isset($props['DAV::getcontentlength'])
				// Don't compress if size is larger than 8 MiB
				&& $props['DAV::getcontentlength'] < 8*1024*1024
				// Don't compress already compressed content
				&& !preg_match('/\.(?:cbz|cbr|cb7|mp4|m4a|zip|docx|xlsx|pptx|ods|odt|odp|7z|gz|bz2|lzma|lz|xz|apk|dmg|jar|rar|webm|ogg|mp3|ogm|flac|ogv|mkv|avi)$/i', $uri)) {
				$gzip = true;
				header('Content-Encoding: gzip', true);
			}

			// Try to avoid common issues with output buffering and stuff
			if (function_exists('apache_setenv')) {
				@apache_setenv('no-gzip', 1);
			}

			@ini_set('zlib.output_compression', 'Off');

			if (@ob_get_length()) {
				@ob_clean();
			}

			if (isset($file['content'])) {
				$length = strlen($file['content']);

				if ($start || $end) {
					if (null !== $end && $end > $length) {
						header('Content-Range: bytes */' . $length, true);
						throw new Exception('End range cannot be satisfied', 416);
					}

					if ($start === null) {
						$start = $length - $end;
						$end = $start + $end;
					}
					elseif ($end === null) {
						$end = $length;
					}

					http_response_code(206);
					header(sprintf('Content-Range: bytes %s-%s/%s', $start, $end - 1, $length));
					$file['content'] = substr($file['content'], $start, $end - $start);
					$length = $end - $start;
				}

				if ($gzip) {
					$file['content'] = gzencode($file['content'], 9);
					$length = strlen($file['content']);
				}

				header('Content-Length: ' . $length, true);
				echo $file['content'];
				return null;
			}

			if (isset($file['path'])) {
				$file['resource'] = fopen($file['path'], 'rb');
			}

			$seek = fseek($file['resource'], 0, SEEK_END);

			if ($seek === 0) {
				$length = ftell($file['resource']);
				fseek($file['resource'], 0, SEEK_SET);
			}

			if (($start || $end) && $seek === 0) {
				if (null !== $end && $end > $length) {
					header('Content-Range: bytes */' . $length, true);
					throw new Exception('End range cannot be satisfied', 416);
				}

				if ($start === null) {
					$start = $length - $end;
					$end = $start + $end;
				}
				elseif ($end === null) {
					$end = $length;
				}

				fseek($file['resource'], $start, SEEK_SET);

				http_response_code(206);
				header(sprintf('Content-Range: bytes %s-%s/%s', $start, $end - 1, $length), true);

				$length = $end - $start;
				$end -= $start;
			}
			elseif (null === $length && isset($file['path'])) {
				$end = $length = filesize($file['path']);
			}

			if ($gzip) {
				$this->log('Using gzip output compression');
				$gzip = deflate_init(ZLIB_ENCODING_GZIP);

				$fp = fopen('php://temp', 'wb');

				while (!feof($file['resource'])) {
					fwrite($fp, deflate_add($gzip, fread($file['resource'], 8192), ZLIB_NO_FLUSH));
				}

				fwrite($fp, deflate_add($gzip, '', ZLIB_FINISH));
				$length = ftell($fp);
				rewind($fp);
				fclose($file['resource']);

				$file['resource'] = $fp;
				unset($fp);
			}

			if (null !== $length) {
				$this->log('Length: %s', $length);
				header('Content-Length: ' . $length, true);
			}

			$block_size = 8192*4;

			while (!feof($file['resource']) && ($end === null || $end > 0)) {
				$l = $end !== null ? min($block_size, $end) : $block_size;

				echo fread($file['resource'], $l);
				flush();

				if (null !== $end) {
					$end -= $block_size;
				}
			}

			fclose($file['resource']);

			return null;
		}

		public function http_copy(string $uri): ?string
		{
			return $this->_http_copymove($uri, 'copy');
		}

		public function http_move(string $uri): ?string
		{
			return $this->_http_copymove($uri, 'move');
		}

		protected function _http_copymove(string $uri, string $method): ?string
		{
			$uri = $this->_prefix($uri);

			$destination = $_SERVER['HTTP_DESTINATION'] ?? null;
			$depth = $_SERVER['HTTP_DEPTH'] ?? 1;

			if (!$destination) {
				throw new Exception('Destination not supplied', 400);
			}

			$destination = $this->getURI($destination);

			if (trim($destination, '/') == trim($uri, '/')) {
				throw new Exception('Cannot move file to itself', 403);
			}

			$overwrite = ($_SERVER['HTTP_OVERWRITE'] ?? null) == 'T';

			// Dolphin is removing the file name when moving to root directory
			if (empty($destination)) {
				$destination = basename($uri);
			}

			$this->log('<= Destination: %s', $destination);
			$this->log('<= Overwrite: %s (%s)', $overwrite ? 'Yes' : 'No', $_SERVER['HTTP_OVERWRITE'] ?? null);

			if (!$overwrite && $this->storage->exists($destination)) {
				throw new Exception('File already exists and overwriting is disabled', 412);
			}

			if ($method == 'move') {
				$this->checkLock($uri);
			}

			$this->checkLock($destination);

			// Moving/copy of directory to an existing destination and depth=0
			// should do just nothing, see 'depth_zero_copy' test in litmus
			if ($depth == 0
				&& $this->storage->exists($destination)
				&& current($this->storage->propfind($destination, ['DAV::resourcetype'], 0)) == 'collection') {
				$overwritten = $this->storage->exists($uri);
			}
			else {
				$overwritten = $this->storage->$method($uri, $destination);
			}

			if ($method == 'move' && ($token = $this->getLockToken())) {
				$this->storage->unlock($uri, $token);
			}

			http_response_code($overwritten ? 204 : 201);
			return null;
		}

		public function http_mkcol(string $uri): ?string
		{
			if (!empty($_SERVER['CONTENT_LENGTH'])) {
				throw new Exception('Unsupported body for MKCOL', 415);
			}

			$uri = $this->_prefix($uri);
			$this->storage->mkcol($uri);

			http_response_code(201);
			return null;
		}

		protected function extractRequestedProperties(string $body): ?array
		{
			// We only care about properties if the client asked for it
			// If not, we consider that the client just requested to get everything
			if (!preg_match('!<(?:\w+:)?propfind!', $body)) {
				return null;
			}

			$ns = [];
			$dav_ns = null;
			$default_ns = null;

			if (preg_match('/<propfind[^>]+xmlns="DAV:"/', $body)) {
				$default_ns = 'DAV:';
			}

			preg_match_all('!xmlns:(\w+)\s*=\s*"([^"]+)"!', $body, $match, PREG_SET_ORDER);

			// Find all aliased xmlns
			foreach ($match as $found) {
				$ns[$found[2]] = $found[1];
			}

			if (isset($ns['DAV:'])) {
				$dav_ns = $ns['DAV:'] . ':';
			}

			$regexp = '/<(' . $dav_ns . 'prop(?!find))[^>]*?>(.*?)<\/\1\s*>/s';
			if (!preg_match($regexp, $body, $match)) {
				return null;
			}

			// Find all properties
			// Allow for empty namespace, see Litmus FAQ for propnullns
			// https://github.com/tolsen/litmus/blob/master/FAQ
			preg_match_all('!<([\w-]+)[^>]*xmlns="([^"]*)"|<(?:([\w-]+):)?([\w-]+)!', $match[2], $match, PREG_SET_ORDER);

			$properties = [];

			foreach ($match as $found) {
				if (isset($found[4])) {
					$url = array_search($found[3], $ns) ?: $default_ns;
					$name = $found[4];
				}
				else {
					$url = $found[2];
					$name = $found[1];
				}

				$properties[$url . ':' . $name] = [
					'name' => $name,
					'ns_alias' => $found[3] ?? null,
					'ns_url' => $url,
				];
			}

			return $properties;
		}

		public function http_propfind(string $uri): ?string
		{
			// We only support depth of 0 and 1
			$depth = isset($_SERVER['HTTP_DEPTH']) && empty($_SERVER['HTTP_DEPTH']) ? 0 : 1;

			$uri = $this->_prefix($uri);
			$body = file_get_contents('php://input');

			if (false !== strpos($body, '<!DOCTYPE ')) {
				throw new Exception('Invalid XML', 400);
			}

			$this->log('Requested depth: %s', $depth);

			// We don't really care about having a correct XML string,
			// but we can get better WebDAV compliance if we do
			if (isset($_SERVER['HTTP_X_LITMUS'])) {
				if (false !== strpos($body, '<!DOCTYPE ')) {
					throw new Exception('Invalid XML', 400);
				}

				$xml = @simplexml_load_string($body);

				if ($e = libxml_get_last_error()) {
					throw new Exception('Invalid XML', 400);
				}
			}

			$requested = $this->extractRequestedProperties($body);
			$requested_keys = $requested ? array_keys($requested) : null;

			// Find root element properties
			$properties = $this->storage->propfind($uri, $requested_keys, $depth);

			if (null === $properties) {
				throw new Exception('This does not exist', 404);
			}

			if (isset($properties['DAV::getlastmodified'])) {
				foreach (self::MODIFICATION_TIME_PROPERTIES as $name) {
					$properties[$name] = $properties['DAV::getlastmodified'];
				}
			}

			$items = [$uri => $properties];

			if ($depth) {
				foreach ($this->storage->list($uri, $requested) as $file => $properties) {
					$path = trim($uri . '/' . $file, '/');
					$properties = $properties ?? $this->storage->propfind($path, $requested_keys, 0);

					if (!$properties) {
						$this->log('!!! Cannot find "%s"', $path);
						continue;
					}

					$items[$path] = $properties;
				}
			}

			// http_response_code doesn't know the 207 status code
			header('HTTP/1.1 207 Multi-Status', true);
			$this->dav_header();
			header('Content-Type: application/xml; charset=utf-8');

			$root_namespaces = [
				'DAV:' => 'd',
				// Microsoft Clients need this special namespace for date and time values (from PEAR/WebDAV)
				'urn:uuid:c2f41010-65b3-11d1-a29f-00aa00c14882/' => 'ns0',
			];

			$i = 0;
			$requested ??= [];

			foreach ($requested as $prop) {
				if ($prop['ns_url'] == 'DAV:' || !$prop['ns_url']) {
					continue;
				}

				if (!array_key_exists($prop['ns_url'], $root_namespaces)) {
					$root_namespaces[$prop['ns_url']] = $prop['ns_alias'] ?: 'rns' . $i++;
				}
			}

			foreach ($items as $properties) {
				foreach ($properties as $name => $value) {
					$pos = strrpos($name, ':');
					$ns = substr($name, 0, strrpos($name, ':'));

					// NULL namespace, see Litmus FAQ for propnullns
					if (!$ns) {
						continue;
					}

					if (!array_key_exists($ns, $root_namespaces)) {
						$root_namespaces[$ns] = 'rns' . $i++;
					}
				}
			}

			$out = '<?xml version="1.0" encoding="utf-8"?>';
			$out .= '<d:multistatus';

			foreach ($root_namespaces as $url => $alias) {
				$out .= sprintf(' xmlns:%s="%s"', $alias, $url);
			}

			$out .= '>';

			foreach ($items as $uri => $item) {
				$e = '<d:response>';

				if ($this->prefix) {
					$uri = substr($uri, strlen($this->prefix));
				}

				$uri = trim(rtrim($this->base_uri, '/') . '/' . ltrim($uri, '/'), '/');
				$path = '/' . str_replace('%2F', '/', rawurlencode($uri));

				if (($item['DAV::resourcetype'] ?? null) == 'collection' && $path != '/') {
					$path .= '/';
				}

				$e .= sprintf('<d:href>%s</d:href>', htmlspecialchars($path, ENT_XML1));
				$e .= '<d:propstat><d:prop>';

				foreach ($item as $name => $value) {
					if (null === $value) {
						continue;
					}

					$pos = strrpos($name, ':');
					$ns = substr($name, 0, strrpos($name, ':'));
					$tag_name = substr($name, strrpos($name, ':') + 1);

					$alias = $root_namespaces[$ns] ?? null;
					$attributes = '';

					// The ownCloud Android app doesn't like formatted dates, it makes it crash.
					// so force it to have a timestamp
					if ($name == 'DAV::creationdate'
						&& ($value instanceof \DateTimeInterface)
						&& false !== stripos($_SERVER['HTTP_USER_AGENT'] ?? '', 'owncloud')) {
						$value = $value->getTimestamp();
					}
					// ownCloud app crashes if mimetype is provided for a directory
					// https://github.com/owncloud/android/issues/3768
					elseif ($name == 'DAV::getcontenttype'
						&& ($item['DAV::resourcetype'] ?? null) == 'collection') {
						$value = null;
					}

					if ($name == 'DAV::resourcetype' && $value == 'collection') {
						$value = '<d:collection />';
					}
					elseif ($name == 'DAV::getetag' && strlen($value) && $value[0] != '"') {
						$value = '"' . $value . '"';
					}
					elseif ($value instanceof \DateTimeInterface) {
						// Change value to GMT
						$value = clone $value;
						$value->setTimezone(new \DateTimeZone('GMT'));
						$value = $value->format(DATE_RFC7231);
					}
					elseif (is_array($value)) {
						$attributes = $value['attributes'] ?? '';
						$value = $value['xml'] ?? null;
					}
					else {
						$value = htmlspecialchars($value, ENT_XML1);
					}

					// NULL namespace, see Litmus FAQ for propnullns
					if (!$ns) {
						$attributes .= ' xmlns=""';
					}
					else {
						$tag_name = $alias . ':' . $tag_name;
					}

					if (null === $value || self::EMPTY_PROP_VALUE === $value) {
						$e .= sprintf('<%s%s />', $tag_name, $attributes ? ' ' . $attributes : '');
					}
					else {
						$e .= sprintf('<%s%s>%s</%1$s>', $tag_name, $attributes ? ' ' . $attributes : '', $value);
					}
				}

				$e .= '</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>' . "\n";

				// Append missing properties
				if (!empty($requested)) {
					$missing_properties = array_diff($requested_keys, array_keys($item));

					if (count($missing_properties)) {
						$e .= '<d:propstat><d:prop>';

						foreach ($missing_properties as $name) {
							$pos = strrpos($name, ':');
							$ns = substr($name, 0, strrpos($name, ':'));
							$name = substr($name, strrpos($name, ':') + 1);
							$alias = $root_namespaces[$ns] ?? null;

							// NULL namespace, see Litmus FAQ for propnullns
							if (!$alias) {
								$e .= sprintf('<%s xmlns="" />', $name);
							}
							else {
								$e .= sprintf('<%s:%s />', $alias, $name);
							}
						}

						$e .= '</d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>';
					}
				}

				$e .= '</d:response>' . "\n";
				$out .= $e;
			}

			$out .= '</d:multistatus>';

			return $out;
		}

		static public function parsePropPatch(string $body): array
		{
			if (false !== strpos($body, '<!DOCTYPE ')) {
				throw new Exception('Invalid XML', 400);
			}

			$xml = @simplexml_load_string($body);

			if (false === $xml) {
				throw new WebDAV_Exception('Invalid XML', 400);
			}

			$_ns = null;

			// Select correct namespace if required
			if (!empty(key($xml->getDocNameSpaces()))) {
				$_ns = 'DAV:';
			}

			$out = [];

			// Process set/remove instructions in order (important)
			foreach ($xml->children($_ns) as $child) {
				foreach ($child->children($_ns) as $prop) {
					$prop = $prop->children();
					if ($child->getName() == 'set') {
						$ns = $prop->getNamespaces(true);
						$ns = array_flip($ns);
						$name = key($ns) . ':' . $prop->getName();

						$attributes = $prop->attributes();
						$attributes = $attributes === null ? null : iterator_to_array($attributes);

						foreach ($ns as $xmlns => $alias) {
							foreach (iterator_to_array($prop->attributes($alias)) as $key => $v) {
								$attributes[$xmlns . ':' . $key] = $value;
							}
						}

						if ($prop->count() > 1) {
							$text = '';

							foreach ($prop->children() as $c) {
								$text .= $c->asXML();
							}
						}
						else {
							$text = (string)$prop;
						}

						$out[$name] = ['action' => 'set', 'attributes' => $attributes ?: null, 'content' => $text ?: null];
					}
					else {
						$ns = $prop->getNamespaces();
						$name = current($ns) . ':' . $prop->getName();
						$out[$name] = ['action' => 'remove'];
					}
				}
			}

			return $out;
		}

		public function http_proppatch(string $uri): ?string
		{
			$uri = $this->_prefix($uri);
			$this->checkLock($uri);

			$prefix = '<?xml version="1.0" encoding="utf-8"?>' . "\n";
			$prefix.= '<d:multistatus xmlns:d="DAV:"';
			$suffix = "</d:multistatus>\n";

			$body = file_get_contents('php://input');

			$properties = $this->parsePropPatch($body);
			$root_namespaces = [];
			$i = 0;
			$set_time = null;
			$set_time_name = null;

			foreach ($properties as $name => $value) {
				$pos = strrpos($name, ':');
				$ns = substr($name, 0, $pos);

				if (!array_key_exists($ns, $root_namespaces)) {
					$alias = 'rns' . $i++;
					$root_namespaces[$ns] = $alias;
					$prefix .= sprintf(' xmlns:%s="%s"', $alias, htmlspecialchars($ns, ENT_XML1));
				}
			}

			// See if the client wants to set the modification time
			foreach (self::MODIFICATION_TIME_PROPERTIES as $name) {
				if (!array_key_exists($name, $properties) || $value['action'] !== 'set' || empty($value['content'])) {
					continue;
				}

				$ts = $value['content'];

				if (ctype_digit($ts)) {
					$ts = '@' . $ts;
				}

				$set_time = new \DateTime($value['content']);
				$set_time_name = $name;
			}

			$prefix .= sprintf(">\n<d:response>\n  <d:href>%s</d:href>\n", htmlspecialchars($url, ENT_XML1));

			// http_response_code doesn't know the 207 status code
			header('HTTP/1.1 207 Multi-Status', true);
			header('Content-Type: application/xml; charset=utf-8', true);

			if (!count($properties)) {
				return $prefix . $suffix;
			}

			if ($set_time) {
				unset($properties[$set_time_name]);
			}

			$return = $this->storage->proppatch($uri, $properties);

			if ($set_time && $this->touch($uri, $set_time)) {
				$return[$set_time_name] = 200;
			}

			$out = '';

			static $messages = [
				200 => 'OK',
				403 => 'Forbidden',
				409 => 'Conflict',
				427 => 'Failed Dependency',
				507 => 'Insufficient Storage',
			];

			foreach ($return as $name => $status) {
				$pos = strrpos($name, ':');
				$ns = substr($name, 0, $pos);
				$name = substr($name, $pos + 1);

				$out .= "  <d:propstat>\n    <d:prop>";
				$out .= sprintf("<%s:%s /></d:prop>\n    <d:status>HTTP/1.1 %d %s</d:status>",
					$root_namespaces[$ns],
					$name,
					$status,
					$messages[$status] ?? ''
				);
				$out .= "\n  </d:propstat>\n";
			}

			$out .= "</d:response>\n";

			return $prefix . $out . $suffix;
		}

		public function http_lock(string $uri): ?string
		{
			$uri = $this->_prefix($uri);
			// We don't use this currently, but maybe later?
			//$depth = !empty($this->_SERVER['HTTP_DEPTH']) ? 1 : 0;
			//$timeout = isset($_SERVER['HTTP_TIMEOUT']) ? explode(',', $_SERVER['HTTP_TIMEOUT']) : [];
			//$timeout = array_map('trim', $timeout);

			if (empty($_SERVER['CONTENT_LENGTH']) && !empty($_SERVER['HTTP_IF'])) {
				$token = $this->getLockToken();

				if (!$token) {
					throw new Exception('Invalid If header', 400);
				}

				$info = null;
				$ns = 'D';
				$scope = self::EXCLUSIVE_LOCK;

				$this->checkLock($uri, $token);
				$this->log('Requesting LOCK refresh: %s = %s', $uri, $scope);
			}
			else {
				$locked_scope = $this->storage->getLock($uri);

				if ($locked_scope == self::EXCLUSIVE_LOCK) {
					throw new Exception('Cannot acquire another lock, resource is locked for exclusive use', 423);
				}

				if ($locked_scope && $token = $this->getLockToken()) {
					$token = $this->getLockToken();

					if (!$token) {
						throw new Exception('Missing lock token', 423);
					}

					$this->checkLock($uri, $token);
				}

				$xml = file_get_contents('php://input');

				if (!preg_match('!<((?:(\w+):)?lockinfo)[^>]*>(.*?)</\1>!is', $xml, $match)) {
					throw new Exception('Invalid XML', 400);
				}

				$ns = $match[2];
				$info = $match[3];

				// Quick and dirty UUID
				$uuid = random_bytes(16);
				$uuid[6] = chr(ord($uuid[6]) & 0x0f | 0x40); // set version to 0100
				$uuid[8] = chr(ord($uuid[8]) & 0x3f | 0x80); // set bits 6-7 to 10
				$uuid = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($uuid), 4));

				$token = 'opaquelocktoken:' . $uuid;
				$scope = false !== stripos($info, sprintf('<%sexclusive', $ns ? $ns . ':' : '')) ? self::EXCLUSIVE_LOCK : self::SHARED_LOCK;

				$this->log('Requesting LOCK: %s = %s', $uri, $scope);
			}

			$this->storage->lock($uri, $token, $scope);

			$timeout = 60*5;
			$info = sprintf('
				<d:lockscope><d:%s /></d:lockscope>
				<d:locktype><d:write /></d:locktype>
				<d:owner>unknown</d:owner>
				<d:depth>%d</d:depth>
				<d:timeout>Second-%d</d:timeout>
				<d:locktoken><d:href>%s</d:href></d:locktoken>
			', $scope, 1, $timeout, $token);

			http_response_code(200);
			header('Content-Type: application/xml; charset=utf-8');
			header(sprintf('Lock-Token: <%s>', $token));

			$out = '<?xml version="1.0" encoding="utf-8"?>' . "\n";
			$out .= '<d:prop xmlns:d="DAV:">';
			$out .= '<d:lockdiscovery><d:activelock>';

			$out .= $info;

			$out .= '</d:activelock></d:lockdiscovery></d:prop>';

			if ($ns != 'D') {
				$out = str_replace('D:', $ns ? $ns . ':' : '', $out);
				$out = str_replace('xmlns:D', $ns ? 'xmlns:' . $ns : 'xmlns', $out);
			}

			return $out;
		}

		public function http_unlock(string $uri): ?string
		{
			$uri = $this->_prefix($uri);
			$token = $this->getLockToken();

			if (!$token) {
				throw new Exception('Invalid Lock-Token header', 400);
			}

			$this->log('<= Lock Token: %s', $token);

			$this->checkLock($uri, $token);

			$this->storage->unlock($uri, $token);

			http_response_code(204);
			return null;
		}

		protected function getLockToken(): ?string
		{
			if (isset($_SERVER['HTTP_LOCK_TOKEN'])
				&& preg_match('/<(.*?)>/', trim($_SERVER['HTTP_LOCK_TOKEN']), $match)) {
				return $match[1];
			}
			elseif (isset($_SERVER['HTTP_IF'])
				&& preg_match('/\(<(.*?)>\)/', trim($_SERVER['HTTP_IF']), $match)) {
				return $match[1];
			}
			else {
				return null;
			}
		}

		protected function checkLock(string $uri, ?string $token = null): void
		{
			if ($token === null) {
				$token = $this->getLockToken();
			}

			// Trying to access using a parent directory
			if (isset($_SERVER['HTTP_IF'])
				&& preg_match('/<([^>]+)>\s*\(<[^>]*>\)/', $_SERVER['HTTP_IF'], $match)) {
				$root = $this->getURI($match[1]);

				if (0 !== strpos($uri, $root)) {
					throw new Exception('Invalid "If" header path: ' . $root, 400);
				}

				$uri = $root;
			}
			// Try to validate token
			elseif (isset($_SERVER['HTTP_IF'])
				&& preg_match('/\(<([^>]*)>\s+\["([^""]+)"\]\)/', $_SERVER['HTTP_IF'], $match)) {
				$token = $match[1];
				$request_etag = $match[2];
				$etag = current($this->storage->propfind($uri, ['DAV::getetag'], 0));

				if ($request_etag != $etag) {
					throw new Exception('Resource is locked and etag does not match', 412);
				}
			}

			if ($token == 'DAV:no-lock') {
				throw new Exception('Resource is locked', 412);
			}

			// Token is valid
			if ($token && $this->storage->getLock($uri, $token)) {
				return;
			}
			elseif ($token) {
				throw new Exception('Invalid token', 400);
			}
			// Resource is locked
			elseif ($this->storage->getLock($uri)) {
				throw new Exception('Resource is locked', 423);
			}
		}

		protected function dav_header()
		{
			header('DAV: 1, 2, 3');
		}

		public function http_options(): void
		{
			http_response_code(200);
			$methods = 'GET HEAD PUT DELETE COPY MOVE PROPFIND MKCOL LOCK UNLOCK';

			$this->dav_header();

			header('Allow: ' . $methods);
			header('Content-length: 0');
			header('Accept-Ranges: bytes');
			header('MS-Author-Via: DAV');
		}

		public function log(string $message, ...$params)
		{
			if (PHP_SAPI == 'cli-server') {
				file_put_contents('php://stderr', vsprintf($message, $params) . "\n");
			}
		}

		protected function getURI(string $source): string
		{
			$uri = parse_url($source, PHP_URL_PATH);
			$uri = rawurldecode($uri);
			$uri = trim($uri, '/');
			$uri = '/' . $uri;

			if ($uri . '/' === $this->base_uri) {
				$uri .= '/';
			}

			if (strpos($uri, $this->base_uri) !== 0) {
				throw new Exception(sprintf('Invalid URI, "%s" is outside of scope "%s"', $uri, $this->base_uri), 400);
			}

			$uri = preg_replace('!/{2,}!', '/', $uri);

			if (false !== strpos($uri, '..')) {
				throw new Exception(sprintf('Invalid URI: "%s"', $uri), 403);
			}

			$uri = substr($uri, strlen($this->base_uri));
			$uri = $this->_prefix($uri);
			return $uri;
		}

		public function route(?string $uri = null): bool
		{
			if (null === $uri) {
				$uri = $_SERVER['REQUEST_URI'] ?? '/';
			}

			$uri = '/' . ltrim($uri, '/');
			$this->original_uri = $uri;

			if ($uri . '/' == $this->base_uri) {
				$uri .= '/';
			}

			if (0 === strpos($uri, $this->base_uri)) {
				$uri = substr($uri, strlen($this->base_uri));
			}
			else {
				$this->log('<= %s is not a managed URL (%s)', $uri, $this->base_uri);
				return false;
			}

			// Add some extra-logging for Litmus tests
			if (isset($_SERVER['HTTP_X_LITMUS']) || isset($_SERVER['HTTP_X_LITMUS_SECOND'])) {
				$this->log('X-Litmus: %s', $_SERVER['HTTP_X_LITMUS'] ?? $_SERVER['HTTP_X_LITMUS_SECOND']);
			}

			$method = $_SERVER['REQUEST_METHOD'] ?? null;

			header_remove('Expires');
			header_remove('Pragma');
			header_remove('Cache-Control');
			header('X-Server: KD2', true);

			// Stop and send reply to OPTIONS before anything else
			if ($method == 'OPTIONS') {
				$this->log('<= OPTIONS');
				$this->http_options();
				return true;
			}

			$uri = rawurldecode($uri);
			$uri = trim($uri, '/');
			$uri = preg_replace('!/{2,}!', '/', $uri);

			$this->log('<= %s /%s', $method, $uri);

			try {
				if (false !== strpos($uri, '..')) {
					throw new Exception(sprintf('Invalid URI: "%s"', $uri), 403);
				}

				// Call 'http_method' class method
				$method = 'http_' . strtolower($method);

				if (!method_exists($this, $method)) {
					throw new Exception('Invalid request method', 405);
				}

				$out = $this->$method($uri);

				$this->log('=> %d', http_response_code());

				if (null !== $out) {
					$this->log('=> %s', $out);
				}

				echo $out;
			}
			catch (Exception $e) {
				$this->error($e);
			}

			return true;
		}

		function error(Exception $e)
		{
			$this->log('=> %d - %s', $e->getCode(), $e->getMessage());

			if ($e->getCode() == 423) {
				// http_response_code doesn't know about 423 Locked
				header('HTTP/1.1 423 Locked');
			}
			else {
				http_response_code($e->getCode());
			}

			header('Content-Type: application/xml; charset=utf-8', true);

			printf('<?xml version="1.0" encoding="utf-8"?><d:error xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns"><s:message>%s</s:message></d:error>', htmlspecialchars($e->getMessage(), ENT_XML1));
		}

		static public function hmac(array $data, string $key = '')
		{
			// Protect against length attacks by pre-hashing data
			$data = array_map('sha1', $data);
			$data = implode(':', $data);

			return hash_hmac('sha1', $data, sha1($key));
		}
	}


		abstract class AbstractStorage
	{

		abstract public function get(string $uri): ?array;

		abstract public function exists(string $uri): bool;

		abstract public function propfind(string $uri, ?array $requested_properties, int $depth): ?array;

		public function proppatch(string $uri, array $properties): array
		{
			// By default, properties are not saved
		}

		abstract public function put(string $uri, $pointer, ?string $hash_algo, ?string $hash): bool;

		abstract public function delete(string $uri): void;

		abstract public function copy(string $uri, string $destination): bool;

		abstract public function move(string $uri, string $destination): bool;

		abstract public function mkcol(string $uri): void;

		abstract public function list(string $uri, array $properties): iterable;

		abstract public function touch(string $uri, \DateTimeInterface $timestamp): bool;

		public function lock(string $uri, string $token, string $scope): void
		{
			// By default locking is not implemented
		}

		public function unlock(string $uri, string $token): void
		{
			// By default locking is not implemented
		}

		public function getLock(string $uri, ?string $token = null): ?string
		{
			// By default locking is not implemented, so NULL is always returned
			return null;
		}
	}

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
		file_put_contents($self_dir . '/.htaccess', str_replace('index.php', basename($self), 'DirectoryIndex disabled

RedirectMatch 404 \\.picodav\\.ini

RewriteEngine On
RewriteBase /

# Uncomment the following 2 lignes to make things a bit faster for
# downloading files, AND you don\'t use PicoDAV users to manage access,
# but a regular .htpasswd file and config for your web server.
#RewriteCond %{REQUEST_FILENAME} !-f [OR]
#RewriteCond %{REQUEST_METHOD} !GET

RewriteRule ^.*$ /index.php [END]
'));
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
			fseek($fp, 55024, SEEK_SET);
			echo fread($fp, 27891);
		}
		else {
			fseek($fp, 55024 + 27891, SEEK_SET);
			echo fread($fp, 7004);
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

?>
var css_url = document.currentScript.src.replace(/\/[^\/]+$/, '') + '/webdav.css';

const WebDAVNavigator = (url, options) => {
	// Microdown
	// https://github.com/commit-intl/micro-down
	const microdown=function(){function l(n,e,r){return"<"+n+(r?" "+Object.keys(r).map(function(n){return r[n]?n+'="'+(a(r[n])||"")+'"':""}).join(" "):"")+">"+e+"</"+n+">"}function c(n,e){return e=n.match(/^[+-]/m)?"ul":"ol",n?"<"+e+">"+n.replace(/(?:[+-]|\d+\.) +(.*)\n?(([ \t].*\n?)*)/g,function(n,e,r){return"<li>"+g(e+"\n"+(t=r||"").replace(new RegExp("^"+(t.match(/^\s+/)||"")[0],"gm"),"").replace(o,c))+"</li>";var t})+"</"+e+">":""}function e(r,t,u,c){return function(n,e){return n=n.replace(t,u),l(r,c?c(n):n)}}function t(n,u){return f(n,[/<!--((.|\n)*?)-->/g,"\x3c!--$1--\x3e",/^("""|```)(.*)\n((.*\n)*?)\1/gm,function(n,e,r,t){return'"""'===e?l("div",p(t,u),{class:r}):u&&u.preCode?l("pre",l("code",a(t),{class:r})):l("pre",a(t),{class:r})},/(^>.*\n?)+/gm,e("blockquote",/^> ?(.*)$/gm,"$1",r),/((^|\n)\|.+)+/g,e("table",/^.*(\n\|---.*?)?$/gm,function(n,t){return e("tr",/\|(-?)([^|]*)\1(\|$)?/gm,function(n,e,r){return l(e||t?"th":"td",g(r))})(n.slice(0,n.length-(t||"").length))}),o,c,/#\[([^\]]+?)]/g,'<a name="$1"></a>',/^(#+) +(.*)(?:$)/gm,function(n,e,r){return l("h"+e.length,g(r))},/^(===+|---+)(?=\s*$)/gm,"<hr>"],p,u)}var i=this,a=function(n){return n?n.replace(/"/g,"&quot;").replace(/</g,"&lt;").replace(/>/g,"&gt;"):""},o=/(?:(^|\n)([+-]|\d+\.) +(.*(\n[ \t]+.*)*))+/g,g=function c(n,i){var o=[];return n=(n||"").trim().replace(/`([^`]*)`/g,function(n,e){return"\\"+o.push(l("code",a(e)))}).replace(/[!&]?\[([!&]?\[.*?\)|[^\]]*?)]\((.*?)( .*?)?\)|(\w+:\/\/[$\-.+!*'()/,\w]+)/g,function(n,e,r,t,u){return u?i?n:"\\"+o.push(l("a",u,{href:u})):"&"==n[0]?(e=e.match(/^(.+),(.+),([^ \]]+)( ?.+?)?$/),"\\"+o.push(l("iframe","",{width:e[1],height:e[2],frameborder:e[3],class:e[4],src:r,title:t}))):"\\"+o.push("!"==n[0]?l("img","",{src:r,alt:e,title:t}):l("a",c(e,1),{href:r,title:t}))}),n=function r(n){return n.replace(/\\(\d+)/g,function(n,e){return r(o[Number.parseInt(e)-1])})}(i?n:r(n))},r=function t(n){return f(n,[/([*_]{1,3})((.|\n)+?)\1/g,function(n,e,r){return e=e.length,r=t(r),1<e&&(r=l("strong",r)),e%2&&(r=l("em",r)),r},/(~{1,3})((.|\n)+?)\1/g,function(n,e,r){return l([,"u","s","del"][e.length],t(r))},/  \n|\n  /g,"<br>"],t)},f=function(n,e,r,t){for(var u,c=0;c<e.length;){if(u=e[c++].exec(n))return r(n.slice(0,u.index),t)+("string"==typeof e[c]?e[c].replace(/\$(\d)/g,function(n,e){return u[e]}):e[c].apply(i,u))+r(n.slice(u.index+u[0].length),t);c++}return n},p=function(n,e){n=n.replace(/[\r\v\b\f]/g,"").replace(/\\./g,function(n){return"&#"+n.charCodeAt(1)+";"});var r=t(n,e);return r!==n||r.match(/^[\s\n]*$/i)||(r=g(r).replace(/((.|\n)+?)(\n\n+|$)/g,function(n,e){return l("p",e)})),r.replace(/&#(\d+);/g,function(n,e){return String.fromCharCode(parseInt(e))})};return{parse:p,block:t,inline:r,inlineBlock:g}}();

	const PREVIEW_TYPES = /^image\/(png|webp|svg|jpeg|jpg|gif|png)|^application\/pdf|^text\/|^audio\/|^video\/|application\/x-empty/;

	const _ = key => typeof lang_strings != 'undefined' && key in lang_strings ? lang_strings[key] : key;

	const rename_button = `<input class="rename" type="button" value="${_('Rename')}" />`;
	const delete_button = `<input class="delete" type="button" value="${_('Delete')}" />`;

	const edit_button = `<input class="edit" type="button" value="${_('Edit')}" />`;

	const mkdir_dialog = `<input type="text" name="mkdir" placeholder="${_('Directory name')}" />`;
	const mkfile_dialog = `<input type="text" name="mkfile" placeholder="${_('File name')}" />`;
	const rename_dialog = `<input type="text" name="rename" placeholder="${_('New file name')}" />`;
	const paste_upload_dialog = `<h3>Upload this file?</h3><input type="text" name="paste_name" placeholder="${_('New file name')}" />`;
	const edit_dialog = `<textarea name="edit" cols="70" rows="30"></textarea>`;
	const markdown_dialog = `<div id="mdp"><textarea name="edit" cols="70" rows="30"></textarea><div id="md"></div></div>`;
	const delete_dialog = `<h3>${_('Confirm delete?')}</h3>`;
	const wopi_dialog = `<iframe id="wopi_frame" name="wopi_frame" allowfullscreen="true" allow="autoplay camera microphone display-capture"
			sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-top-navigation allow-popups-to-escape-sandbox allow-downloads allow-modals">
		</iframe>`;

	const dialog_tpl = `<dialog open><p class="close"><input type="button" value="&#x2716; ${_('Close')}" class="close" /></p><form><div>%s</div>%b</form></dialog>`;

	const html_tpl = `<!DOCTYPE html><html>
		<head><title>Files</title><link rel="stylesheet" type="text/css" href="${css_url}" /></head>
		<body><main></main><div class="bg"></div></body></html>`;

	const body_tpl = `<h1>%title%</h1>
		<div class="upload">
			<select class="sortorder btn">
				<option value="name">${_('Sort by name')}</option>
				<option value="date">${_('Sort by date')}</option>
				<option value="size">${_('Sort by size')}</option>
			</select>
			<input type="button" class="download_all" value="${_('Download all files')}" />
		</div>
		<table>%table%</table>`;

	const create_buttons = `<input class="mkdir" type="button" value="${_('New directory')}" />
			<input type="file" style="display: none;" />
			<input class="mkfile" type="button" value="${_('New text file')}" />
			<input class="uploadfile" type="button" value="${_('Upload file')}" />`;

	const dir_row_tpl = `<tr data-permissions="%permissions%"><td class="thumb"><span class="icon dir"><b>%icon%</b></span></td><th colspan="2"><a href="%uri%">%name%</a></th><td>%modified%</td><td class="buttons"><div></div></td></tr>`;
	const file_row_tpl = `<tr data-permissions="%permissions%" data-mime="%mime%" data-size="%size%"><td class="thumb"><span class="icon %icon%"><b>%icon%</b></span></td><th><a href="%uri%">%name%</a></th><td class="size">%size_bytes%</td><td>%modified%</td><td class="buttons"><div><a href="%uri%" download class="btn">${_('Download')}</a></div></td></tr>`;

	const propfind_tpl = '<'+ `?xml version="1.0" encoding="UTF-8"?>
		<D:propfind xmlns:D="DAV:" xmlns:oc="http://owncloud.org/ns">
			<D:prop>
				<D:getlastmodified/><D:getcontenttype/><D:getcontentlength/><D:resourcetype/><D:displayname/><oc:permissions/>
			</D:prop>
		</D:propfind>`;

	const wopi_propfind_tpl = '<' + `?xml version="1.0" encoding="UTF-8"?>
		<D:propfind xmlns:D="DAV:" xmlns:W="https://interoperability.blob.core.windows.net/files/MS-WOPI/">
			<D:prop>
				<W:file-url/><W:token/><W:token-ttl/>
			</D:prop>
		</D:propfind>`;

	const html = (unsafe) => {
		return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
	};

	const reqXML = (method, url, body, headers) => {
		return req(method, url, body, headers).then((r) => {
				if (!r.ok) {
					throw new Error(r.status + ' ' + r.statusText);
				}
				return r.text();
			}).then(str => new window.DOMParser().parseFromString(str, "text/xml"));
	};

	const reqAndReload = (method, url, body, headers) => {
		animateLoading();
		req(method, url, body, headers).then(r => {
			stopLoading();
			if (!r.ok) {
				return r.text().then(t => {
					var message;
					if (a = t.match(/<((?:\w+:)?message)>(.*)<\/\1>/)) {
						message = "\n" + a[2];
					}

					throw new Error(r.status + ' ' + r.statusText + message); });
			}
			reloadListing();
		}).catch(e => {
			console.error(e);
			alert(e);
		});
		return false;
	};

	const req = (method, url, body, headers) => {
		if (!headers) {
			headers = {};
		}

		if (auth_header) {
			headers.Authorization = auth_header;
		}

		return fetch(url, {method, body, headers});
	};

	const xhr = (method, url, progress_callback) => {
		var xhr = new XMLHttpRequest();
		current_xhr = xhr;
		xhr.responseType = 'blob';
		var p = new Promise((resolve, reject) => {
			xhr.open(method, url);
			xhr.onload = function () {
				if (this.status >= 200 && this.status < 300) {
					resolve(xhr.response);
				} else {
					reject({
						status: this.status,
						statusText: xhr.statusText
					});
				}
			};
			xhr.onerror = function () {
				reject({
					status: this.status,
					statusText: xhr.statusText
				});
			};
			xhr.onprogress = progress_callback;
			xhr.send();
		});
		return p;
	};

	const get_url = async (url) => {
		var progress = (e) => {
			var p = $('progress');
			if (!p || e.loaded <= 0) return;
			p.value = e.loaded;
			$('.progress_bytes').innerHTML = formatBytes(e.loaded);
		};

		if (temp_object_url) {
			window.URL.revokeObjectURL(temp_object_url);
		}

		return await xhr('GET', url, progress).then(blob => {
			temp_object_url = window.URL.createObjectURL(blob);
			return temp_object_url;
		});
	};

	const wopi_init = async () => {
		try {
			var d = await reqXML('GET', wopi_discovery_url);
		}
		catch (e) {
			reloadListing();
			return;
		}

		d.querySelectorAll('app').forEach(app => {
			var mime = (a = app.getAttribute('name').match(/^.*\/.*$/)) ? a[0] : null;
			wopi_mimes[mime] = {};

			app.querySelectorAll('action').forEach(action => {
				var ext = action.getAttribute('ext').toUpperCase();
				var url = action.getAttribute('urlsrc').replace(/<[^>]*&>/g, '');
				var name = action.getAttribute('name');

				if (mime) {
					wopi_mimes[mime][name] = url;
				}
				else {
					if (!wopi_extensions.hasOwnProperty(ext)) {
						wopi_extensions[ext] = {};
					}

					wopi_extensions[ext][name] = url;
				}
			});
		});

		reloadListing();
	};

	const wopi_getEditURL = (name, mime) => {
		var file_ext = name.replace(/^.*\.(\w+)$/, '$1').toUpperCase();

		if (wopi_mimes.hasOwnProperty(mime) && wopi_mimes[mime].hasOwnProperty('edit')) {
			return wopi_mimes[mime].edit;
		}
		else if (wopi_extensions.hasOwnProperty(file_ext) && wopi_extensions[file_ext].hasOwnProperty('edit')) {
			return wopi_extensions[file_ext].edit;
		}

		return null;
	};

	const wopi_getViewURL = (name, mime) => {
		var file_ext = name.replace(/^.*\.(\w+)$/, '$1').toUpperCase();

		if (wopi_mimes.hasOwnProperty(mime) && wopi_mimes[mime].hasOwnProperty('view')) {
			return wopi_mimes[mime].view;
		}
		else if (wopi_extensions.hasOwnProperty(file_ext) && wopi_extensions[file_ext].hasOwnProperty('view')) {
			return wopi_extensions[file_ext].view;
		}

		return wopi_getEditURL(name, mime);
	};

	const wopi_open = async (document_url, wopi_url) => {
		var properties = await reqXML('PROPFIND', document_url, wopi_propfind_tpl, {'Depth': '0'});
		var src = (a = properties.querySelector('file-url')) ? a.textContent : null;
		var token = (a = properties.querySelector('token')) ? a.textContent : null;
		var token_ttl = (a = properties.querySelector('token-ttl')) ? a.textContent : +(new Date(Date.now() + 3600 * 1000));

		if (!src || !token) {
			alert('Cannot open document: WebDAV server did not return WOPI properties');
		}

		wopi_url += '&WOPISrc=' + encodeURIComponent(src);

		openDialog(wopi_dialog, false);
		$('dialog').className = 'preview';

		var f = $('dialog form');
		f.target = 'wopi_frame';
		f.action = wopi_url;
		f.method = 'post';
		f.insertAdjacentHTML('beforeend', `<input name="access_token" value="${token}" type="hidden" /><input name="access_token_ttl" value="${token_ttl}" type="hidden" />`);
		f.submit();
	};

	const template = (tpl, params) => {
		return tpl.replace(/%(\w+)%/g, (a, b) => {
			return params[b];
		});
	};

	const openDialog = (html, ok_btn = true) => {
		var tpl = dialog_tpl.replace(/%b/, ok_btn ? `<p><input type="submit" value="${_('OK')}" /></p>` : '');
		$('body').classList.add('dialog');
		$('body').insertAdjacentHTML('beforeend', tpl.replace(/%s/, html));
		$('.close input').onclick = closeDialog;
		evt = window.addEventListener('keyup', (e) => {
			if (e.key != 'Escape') return;
			closeDialog();
			return false;
		});
		if (a = $('dialog form input, dialog form textarea')) a.focus();
	};

	const closeDialog = (e) => {
		if (!$('body').classList.contains('dialog')) {
			return;
		}

		if (current_xhr) {
			current_xhr.abort();
			current_xhr = null;
		}

		window.onbeforeunload = null;

		$('body').classList.remove('dialog');
		if (!$('dialog')) return;
		$('dialog').remove();
		window.removeEventListener('keyup', evt);
		evt = null;
	};

	const download = async (name, size, url) => {
		window.onbeforeunload = () => {
			if (current_xhr) {
				current_xhr.abort();
			}

			return true;
		};

		openDialog(`<p class="spinner"><span></span></p>
			<h3>${html(name)}</h3>
			<progress max="${size}"></progress>
			<p><span class="progress_bytes"></span> / ${formatBytes(size)}</p>`, false);

		await get_url(url);
		const a = document.createElement('a');
		a.style.display = 'none';
		a.href = temp_object_url;
		a.download = name;
		document.body.appendChild(a);
		a.click();
		window.URL.revokeObjectURL(temp_object_url);
		a.remove();

		closeDialog();
		window.onbeforeunload = null;
	};

	const download_all = async () => {
		for (var i = 0; i < items.length; i++) {
			var item = items[i];
			if (item.is_dir) {
				continue;
			}

			await download(item.name, item.size, item.uri)
		}
	};

	const preview = (type, url) => {
		if (type.match(/^image\//)) {
			openDialog(`<img src="${url}" />`, false);
		}
		else if (type.match(/^audio\//)) {
			openDialog(`<audio controls="true" autoplay="true" src="${url}" />`, false);
		}
		else if (type.match(/^video\//)) {
			openDialog(`<video controls="true" autoplay="true" src="${url}" />`, false);
		}
		else {
			openDialog(`<iframe src="${url}" />`, false);
		}

		$('dialog').className = 'preview';
	};

	const $ = (a) => document.querySelector(a);

	const formatBytes = (bytes) => {
		const unit = _('B');

		if (bytes >= 1024*1024*1024) {
			return Math.round(bytes / (1024*1024*1024)) + ' G' + unit;
		}
		else if (bytes >= 1024*1024) {
			return Math.round(bytes / (1024*1024)) + ' M' + unit;
		}
		else if (bytes >= 1024) {
			return Math.round(bytes / 1024) + ' K' + unit;
		}
		else {
			return bytes + '  ' + unit;
		}
	};

	const formatDate = (date) => {
		if (isNaN(date)) {
			return '';
		}

		var now = new Date;
		var nb_hours = (+(now) - +(date)) / 3600 / 1000;

		if (date.getFullYear() == now.getFullYear() && date.getMonth() == now.getMonth() && date.getDate() == now.getDate()) {
			if (nb_hours <= 1) {
				return _('%d minutes ago').replace(/%d/, Math.round(nb_hours * 60));
			}
			else {
				return _('%d hours ago').replace(/%d/, Math.round(nb_hours));
			}
		}
		else if (nb_hours <= 24) {
			return _('Yesterday, %s').replace(/%s/, date.toLocaleTimeString());
		}

		return date.toLocaleString();
	};

	const openListing = (uri, push) => {
		closeDialog();

		reqXML('PROPFIND', uri, propfind_tpl, {'Depth': 1}).then((xml) => {
			buildListing(uri, xml)
			current_url = uri;
			changeURL(uri, push);
		}).catch((e) => {
			console.error(e);
			alert(e);
		});
	};

	const reloadListing = () => {
		stopLoading();
		openListing(current_url, false);
	};

	const normalizeURL = (url) => {
		if (!url.match(/^https?:\/\//)) {
			url = base_url.replace(/^(https?:\/\/[^\/]+\/).*$/, '$1') + url.replace(/^\/+/, '');
		}

		return url;
	};

	const changeURL = (uri, push) => {
		try {
			if (push) {
				history.pushState(1, null, uri);
			}
			else {
				history.replaceState(1, null, uri);
			}

			if (popstate_evt) return;

			popstate_evt = window.addEventListener('popstate', (e) => {
				var url = location.pathname;
				openListing(url, false);
			});
		}
		catch (e) {
			// If using a HTML page on another origin
			location.hash = uri;
		}
	};

	const animateLoading = () => {
		document.body.classList.add('loading');
	};

	const stopLoading = () => {
		document.body.classList.remove('loading');
	};

	const buildListing = (uri, xml) => {
		uri = normalizeURL(uri);

		items = [[], []];
		var title = null;
		var root_permissions = null;

		xml.querySelectorAll('response').forEach((node) => {
			var item_uri = normalizeURL(node.querySelector('href').textContent);
			var props = null;

			node.querySelectorAll('propstat').forEach((propstat) => {
				if (propstat.querySelector('status').textContent.match(/200/)) {
					props = propstat;
				}
			});

			// This item didn't return any properties, everything is 404?
			if (!props) {
				console.error('Cannot find properties for: ' + item_uri);
				return;
			}

			var name = item_uri.replace(/\/$/, '').split('/').pop();
			name = decodeURIComponent(name);

			var permissions = (prop = node.querySelector('permissions')) ? prop.textContent : null;

			if (item_uri == uri) {
				title = name;
				root_permissions = permissions;
				return;
			}

			var is_dir = node.querySelector('resourcetype collection') ? true : false;
			var index = sort_order == 'name' && is_dir ? 0 : 1;

			items[index].push({
				'uri': item_uri,
				'name': name,
				'size': !is_dir && (prop = node.querySelector('getcontentlength')) ? parseInt(prop.textContent, 10) : null,
				'mime': !is_dir && (prop = node.querySelector('getcontenttype')) ? prop.textContent : null,
				'modified': (prop = node.querySelector('getlastmodified')) ? new Date(prop.textContent) : null,
				'is_dir': is_dir,
				'permissions': permissions,
			});
		});

		if (sort_order == 'name') {
			items[0].sort((a, b) => a.name.localeCompare(b.name));
		}

		items[1].sort((a, b) => {
			if (sort_order == 'date') {
				return b.modified - a.modified;
			}
			else if (sort_order == 'size') {
				return b.size - a.size;
			}
			else {
				return a.name.localeCompare(b.name);
			}
		});

		if (sort_order == 'name') {
			// Sort with directories first
			items = items[0].concat(items[1]);
		}
		else {
			items = items[1];
		}


		var table = '';
		var parent = uri.replace(/\/+$/, '').split('/').slice(0, -1).join('/') + '/';

		if (parent.length >= base_url.length) {
			table += template(dir_row_tpl, {'name': _('Back'), 'uri': parent, 'icon': '&#x21B2;'});
		}
		else {
			title = 'My files';
		}

		items.forEach(item => {
			// Don't include files we cannot read
			if (item.permissions !== null && item.permissions.indexOf('G') == -1) {
				console.error('OC permissions deny read access to this file: ' + item.name, 'Permissions: ', item.permissions);
				return;
			}

			var row = item.is_dir ? dir_row_tpl : file_row_tpl;
			item.size_bytes = item.size !== null ? formatBytes(item.size).replace(/ /g, '&nbsp;') : null;
			item.icon = item.is_dir ? '&#x1F4C1;' : (item.uri.indexOf('.') > 0 ? item.uri.replace(/^.*\.(\w+)$/, '$1').toUpperCase() : '');
			item.modified = item.modified !== null ? formatDate(item.modified) : null;
			item.name = html(item.name);
			table += template(row, item);
		});

		document.title = title;
		document.querySelector('main').innerHTML = template(body_tpl, {'title': html(document.title), 'base_url': base_url, 'table': table});

		var select = $('.sortorder');
		select.value = sort_order;
		select.onchange = () => {
			sort_order = select.value;
			window.localStorage.setItem('sort_order', sort_order);
			reloadListing();
		};

		if (!items.length) {
			$('.download_all').disabled = true;
		}
		else {
			$('.download_all').onclick = download_all;
		}

		if (!root_permissions || root_permissions.indexOf('C') != -1 || root_permissions.indexOf('K') != -1) {
			$('.upload').insertAdjacentHTML('afterbegin', create_buttons);

			$('.mkdir').onclick = () => {
				openDialog(mkdir_dialog);
				document.forms[0].onsubmit = () => {
					var name = $('input[name=mkdir]').value;

					if (!name) return false;

					name = encodeURIComponent(name);

					req('MKCOL', current_url + name).then(() => openListing(current_url + name + '/'));
					return false;
				};
			};

			$('.mkfile').onclick = () => {
				openDialog(mkfile_dialog);
				var t = $('input[name=mkfile]');
				t.value = '.md';
				t.focus();
				t.selectionStart = t.selectionEnd = 0;
				document.forms[0].onsubmit = () => {
					var name = t.value;

					if (!name) return false;

					name = encodeURIComponent(name);

					return reqAndReload('PUT', current_url + name, '');
				};
			};

			var fi = $('input[type=file]');

			$('.uploadfile').onclick = () => fi.click();

			fi.onchange = () => {
				if (!fi.files.length) return;

				var body = new Blob(fi.files);
				var name = fi.files[0].name;

				name = encodeURIComponent(name);

				return reqAndReload('PUT', current_url + name, body);
			};
		}

		Array.from($('table').rows).forEach((tr) => {
			var $$ = (a) => tr.querySelector(a);
			var file_url = $$('a').href;
			var file_name = $$('a').innerText;
			var dir = $$('[colspan]');
			var mime = !dir ? tr.getAttribute('data-mime') : 'dir';
			var buttons = $$('td.buttons div');
			var permissions = tr.getAttribute('data-permissions');
			var size = tr.getAttribute('data-size');

			if (permissions == 'null') {
				permissions = null;
			}

			if (dir) {
				$$('a').onclick = () => {
					openListing(file_url, true);
					return false;
				};
			}

			// For back link
			if (dir && $$('a').getAttribute('href').length < uri.length) {
				dir.setAttribute('colspan', 4);
				tr.querySelector('td:last-child').remove();
				tr.querySelector('td:last-child').remove();
				return;
			}

			// This is to get around CORS when not on the same domain
			if (user && password && (a = tr.querySelector('a[download]'))) {
				a.onclick = () => {
					download(file_name, size, url);
					return false;
				};
			}

			// Add rename/delete buttons
			if (!permissions || permissions.indexOf('NV') != -1) {
				buttons.insertAdjacentHTML('afterbegin', rename_button);

				$$('.rename').onclick = () => {
					openDialog(rename_dialog);
					let t = $('input[name=rename]');
					t.value = file_name;
					t.focus();
					t.selectionStart = 0;
					t.selectionEnd = file_name.lastIndexOf('.');
					document.forms[0].onsubmit = () => {
						var name = t.value;

						if (!name) return false;

						name = encodeURIComponent(name);
						name = name.replace(/%2F/, '/');

						var dest = current_url + name;
						dest = normalizeURL(dest);

						return reqAndReload('MOVE', file_url, '', {'Destination': dest});
					};
				};

			}

			if (!permissions || permissions.indexOf('D') != -1) {
				buttons.insertAdjacentHTML('afterbegin', delete_button);

				$$('.delete').onclick = (e) => {
					openDialog(delete_dialog);
					document.forms[0].onsubmit = () => {
						return reqAndReload('DELETE', file_url);
					};
				};
			}

			var view_url, edit_url;

			// Don't preview PDF in mobile
			if (mime.match(PREVIEW_TYPES)
				&& !(mime == 'application/pdf' && window.navigator.userAgent.match(/Mobi|Tablet|Android|iPad|iPhone/))) {
				$$('a').onclick = () => {
					if (file_url.match(/\.md$/)) {
						openDialog('<div class="md_preview"></div>', false);
						$('dialog').className = 'preview';
						req('GET', file_url).then(r => r.text()).then(t => {
							$('.md_preview').innerHTML = microdown.parse(html(t));
						});
						return false;
					}

					if (user && password) {
						(async () => { preview(mime, await get_url(file_url)); })();
					}
					else {
						preview(mime, file_url);
					}

					return false;
				};
			}
			else if (view_url = wopi_getViewURL(file_url, mime)) {
				$$('.icon').classList.add('document');
				$$('a').onclick = () => { wopi_open(file_url, view_url); return false; };
			}
			else if (user && password && !dir) {
				$$('a').onclick = () => { download(file_name, size, file_url); return false; };
			}
			else {
				$$('a').download = file_name;
			}

			if (!permissions || permissions.indexOf('W') != -1) {
				if (mime.match(/^text\/|application\/x-empty/)) {
					buttons.insertAdjacentHTML('beforeend', edit_button);

					$$('.edit').onclick = (e) => {
						req('GET', file_url).then((r) => r.text().then((t) => {
							let md = file_url.match(/\.md$/);
							openDialog(md ? markdown_dialog : edit_dialog);
							var txt = $('textarea[name=edit]');
							txt.value = t;

							// Markdown editor
							if (md) {
								let pre = $('#md');

								txt.oninput = () => {
									pre.innerHTML = microdown.parse(html(txt.value));
								};

								txt.oninput();

								// Sync scroll, not perfect but better than nothing
								txt.onscroll = (e) => {
									var p = e.target.scrollTop / (e.target.scrollHeight - e.target.offsetHeight);
									var target = e.target == pre ? txt : pre;
									target.scrollTop = p * (target.scrollHeight - target.offsetHeight);
									e.preventDefault();
									return false;
								};
							}

							document.forms[0].onsubmit = () => {
								var content = txt.value;

								return reqAndReload('PUT', file_url, content);
							};
						}));
					};
				}
				else if (edit_url = wopi_getEditURL(file_url, mime)) {
					buttons.insertAdjacentHTML('beforeend', edit_button);

					$$('.icon').classList.add('document');
					$$('.edit').onclick = () => { wopi_open(file_url, edit_url); return false; };
				}
			}
		});
	};

	var items = [[], []];
	var current_xhr = null;
	var current_url = url;
	var base_url = url;
	const user = options.user || null;
	const password = options.password || null;
	var auth_header = (user && password) ? 'Basic ' + btoa(user + ':' + password) : null;

	if (location.pathname.indexOf(base_url) === 0) {
		current_url = location.pathname;
	}

	if (!base_url.match(/^https?:/)) {
		base_url = location.href.replace(/^(https?:\/\/[^\/]+\/).*$/, '$1') + base_url.replace(/^\/+/, '');
	}

	var evt, paste_upload, popstate_evt, temp_object_url;
	var sort_order = window.localStorage.getItem('sort_order') || 'name';
	var wopi_mimes = {}, wopi_extensions = {};

	const wopi_discovery_url = options.wopi_discovery_url || null;

	document.querySelector('html').innerHTML = html_tpl;

	// Wait for WOPI discovery before creating the list
	if (wopi_discovery_url) {
		wopi_init();
	} else {
		reloadListing();
	}

	window.addEventListener('paste', (e) => {
		let items = e.clipboardData.items;
		const IMAGE_MIME_REGEX = /^image\/(p?jpeg|gif|png)$/i;

		for (var i = 0; i < items.length; i++) {
			if (items[i].kind === 'file' || IMAGE_MIME_REGEX.test(items[i].type)) {
				e.preventDefault();
				let f = items[i].getAsFile();
				let name = f.name == 'image.png' ? f.name.replace(/\./, '-' + (+(new Date)) + '.') : f.name;

				paste_upload = f;

				openDialog(paste_upload_dialog);

				let t = $('input[name=paste_name]');
				t.value = name;
				t.focus();
				t.selectionStart = 0;
				t.selectionEnd = name.lastIndexOf('.');

				document.forms[0].onsubmit = () => {
					name = encodeURIComponent(t.value);
					return reqAndReload('PUT', current_url + name, paste_upload);
				};

				return;
			}
		}
	});

	var dragcounter = 0;

	window.addEventListener('dragover', (e) => {
		e.preventDefault();
		e.stopPropagation();
	});

	window.addEventListener('dragenter', (e) => {
		e.preventDefault();
		e.stopPropagation();

		if (!dragcounter) {
			document.body.classList.add('dragging');
		}

		dragcounter++;
	});

	window.addEventListener('dragleave', (e) => {
		e.preventDefault();
		e.stopPropagation();
		dragcounter--;

		if (!dragcounter) {
			document.body.classList.remove('dragging');
		}
	});

	window.addEventListener('drop', (e) => {
		e.preventDefault();
		e.stopPropagation();
		document.body.classList.remove('dragging');
		dragcounter = 0;

		const files = [...e.dataTransfer.items].map(item => item.getAsFile());

		if (!files.length) return;

		animateLoading();

		(async () => {
			for (var i = 0; i < files.length; i++) {
				var f = files[i]
				await req('PUT', current_url + encodeURIComponent(f.name), f);
			}

			window.setTimeout(() => {
				stopLoading();
				reloadListing();
			}, 500);
		})();
	});
};

if (url = document.querySelector('html').getAttribute('data-webdav-url')) {
	WebDAVNavigator(url, {
		'wopi_discovery_url': document.querySelector('html').getAttribute('data-wopi-discovery-url'),
	});
}
:root {
	--bg-color: #fff;
	--fg-color: #000;
	--g1-color: #eee;
	--g2-color: #ccc;
	--g3-color: #999;
	--link-color: blue;
	--visited-color: purple;
	--active-color: darkred;
}

body {
	text-align: center;
	font-size: 1.1em;
	font-family: Arial, Helvetica, sans-serif;
	background: var(--bg-color);
	color: var(--fg-color);
}

a:link {
	color: var(--link-color);
}

a:visited {
	color: var(--visited-color);
}

a:hover {
	color: var(--active-color);
}

table {
	margin: 2em auto;
	border-collapse: collapse;
	width: 90%;
}

th, td {
	padding: .5em;
	text-align: left;
	border: 2px solid var(--g2-color);
}

th {
	word-break: break-all;
}

td.thumb {
	width: 5%;
}

td.buttons {
	text-align: right;
	width: 20em;
}

td.buttons div {
	display: flex;
	flex-direction: row-reverse;
}

table tr:nth-child(even) {
	background: var(--g1-color);
}

.icon {
	width: 2.6em;
	height: 2.6em;
	display: block;
	border-radius: .2em;
	background:var(--g3-color);
	overflow: hidden;
	color: var(--bg-color);
	text-align: center;
}

.icon b {
	font-weight: normal;
	display: inline-block;
	transform: rotate(-30deg);
	line-height: 2.6rem;
}

.icon.JPEG, .icon.PNG, .icon.JPG, .icon.GIF, .icon.SVG, .icon.WEBP {
	background: #966;
}

.icon.TXT, .icon.MD {
	background: var(--fg-color);
}

.icon.MP4, .icon.MKV, .icon.MP3, .icon.M4A, .icon.WAV, .icon.FLAC, .icon.OGG, .icon.OGV, .icon.AAC, .icon.WEBM {
	background: #669;
}

.icon.document {
	background: #696;
}

.icon.PDF {
	background: #969;
}

.icon.dir {
	background: var(--g2-color);
	color: var(--fg-color);
}

.icon.dir b {
	font-size: 2em;
	transform: none;
}

.size {
	text-align: right;
}

input[type=button], input[type=submit], .btn {
	font-size: 1.2em;
	padding: .3em .5em;
	margin: .2em .3em;
	border: none;
	background: var(--g2-color);
	border-radius: .2em;
	cursor: pointer;
	text-decoration: none;
	color: var(--fg-color) !important;
	font-family: inherit;
}

td input[type=button], td input[type=submit], td .btn {
	font-size: 1em;
}

input[type=text], textarea {
	font-size: 1.2em;
	padding: .3em .5em;
	border: none;
	background: var(--bg-color);
	border-radius: .2em;
	width: calc(100% - 1em);
	color: var(--fg-color);
}

input:focus, textarea:focus {
	box-shadow: 0px 0px 5px var(--active-color);
	outline: 1px solid var(--active-color);
}

input[type=button]:hover, input[type=submit]:hover, .btn:hover {
	color: var(--active-color);
	text-decoration: underline;
	background: var(--bg-color);
	box-shadow: 0px 0px 5px var(--fg-color);
}

.close {
	text-align: right;
	margin: 0;
}

.close input {
	font-size: .8em;
}

input[type=submit] {
	float: right;
}

dialog {
	position: fixed;
	top: 1em;
	right: 1em;
	bottom: 1em;
	left: 1em;
	box-shadow: 0px 0px 5px var(--fg-color);
	background: var(--g1-color);
	color: var(--fg-color);
	border: none;
	border-radius: .5em;
}

dialog form div {
	clear: both;
	margin: 2em 0;
	text-align: center;
}

.upload {
	margin: 1em 0;
}

#mdp div, #mdp textarea {
	width: calc(100% - 1em);
	padding: .5em;
	font-size: 1em;
	height: calc(100% - 1em);
	text-align: left;
	margin: 0;
}

#md {
	overflow: hidden;
	overflow-x: auto;
}

#mdp {
	display: grid;
	grid-template-columns: 1fr 1fr;
	grid-gap: .2em;
	background: var(--g1-color);
	height: 82vh;
}

dialog.preview {
	height: calc(100%);
	width: calc(100%);
	top: 0;
	left: 0;
	right: 0;
	bottom: 0;
	padding: 0;
	border-radius: 0;
	background: var(--g1-color);
	overflow: hidden;
}

iframe, .md_preview {
	overflow: auto;
	position: absolute;
	top: 0;
	left: 0;
	right: 0;
	bottom: 0;
	padding: 0;
	margin: 0;
	width: 100%;
	height: 100%;
	border: none;
}

iframe, iframe body, .md_preview {
	background-color: #fff;
	color: #000;
}

.preview form {
	height: calc(100% - 2em);
	display: flex;
	align-items: center;
	justify-content: center;
}

.preview form > div {
	width: calc(100vw);
	height: 100%;
	position: relative;
	margin: 0;
	display: flex;
	align-items: center;
	justify-content: center;
}

.preview div video {
	max-width: 100%;
	max-height: 100%;
}

.md_preview {
	width: calc(100vw - 2em);
	height: calc(100vh - 2em);
	padding: 1em;
	text-align: left;
}

.preview .close {
	height: 2em;
	text-align: center;
	font-size: 1em;
	display: block;
	width: 100%;
	margin: 0;
	padding: 0;
	border-radius: 0;
	background: var(--g2-color);
	color: var(--fg-color);
	box-shadow: 0px 0px 5px var(--g2-color);
}

.preview img {
	max-width: 95%;
	max-height: 95%;
}

input[name=rename], input[name=paste_name] {
	width: 30em;
}

.bg {
	align-items: center;
	justify-content: center;
	position: fixed;
	top: 0;
	left: 0;
	right: 0;
	bottom: 0;
	margin: 0;
	padding: 0;
	width: 0;
	height: 0;
	border: none;
	align-items: center;
	justify-content: center;
	opacity: 0;
	display: flex;
}

.loading .bg::after, .spinner span::after {
	display: block;
	content: " ";
	width: 70px;
	height: 70px;
	border: 5px solid var(--g2-color);
	border-radius: 50%;
	border-top-color: var(--fg-color);
	animation: spin 1s ease-in-out infinite;
	filter: none;
}

.loading .bg::before {
	display: block;
	content: " ";
	width: 70px;
	height: 70px;
	border: 20px solid var(--bg-color);
	border-radius: 50%;
	background: var(--bg-color);
	position: absolute;
}

.spinner {
	align-items: center;
	justify-content: center;
	display: flex;
}

.spinner span::after {
	width: 30px;
	height: 30px;
}

.loading .bg, .dragging .bg, .dialog .bg {
	backdrop-filter: blur(5px);
	background: rgba(0, 0, 0, 0.5);
	opacity: 1;
	width: 100%;
	height: 100%;
}

dialog {
	transition: all .3s;
}

progress {
	height: 2em;
	width: 90%;
}

@keyframes spin { to { transform: rotate(360deg); } }

@media screen and (max-width: 800px) {
	.upload {
		display: flex;
		flex-direction: row;
		justify-content: center;
		flex-wrap: wrap;
	}

	body {
		margin: 0;
		font-size: 1em;
	}

	table {
		margin: 2em 0;
		width: 100%;
		display: flex;
		flex-direction: column;
	}

	table tr {
		display: block;
		border-top: 5px solid var(--bg-color);
		padding: 0;
		padding-left: 2em;
		position: relative;
		text-align: left;
		min-height: 2.5em;
	}

	table td, table th {
		border: none;
		display: inline-block;
		padding: .2em .5em;
	}

	table td.buttons {
		display: block;
		width: auto;
		text-align: left;
	}

	 td.buttons div {
	 	display: inline-block;
	 }

	table td.thumb {
		padding: 0;
		width: 2em;
		position: absolute;
		left: 0;
		top: 0;
		bottom: 0;
	}

	table th {
		display: block;
	}

	.icon {
		font-size: 12px;
		height: 100%;
		border-radius: 0;
	}

	.icon:not(.dir) b {
		line-height: 3em;
		display: block;
		transform: translateX(-50%) translateY(-50%) rotate(-90deg);
		font-size: 2em;
		height: 3em;
		position: absolute;
		top: 50%;
		left: 50%;
	}

	table th a {
		font-size: 1.2em;
	}

	input[name=rename], input[name=paste_name] {
		width: auto;
	}
}

@media (prefers-color-scheme: dark) {
    :root {
	 	--bg-color: #000;
		--fg-color: #fff;
		--g1-color: #222;
		--g2-color: #555;
		--g3-color: #777;
		--link-color: #99f;
		--visited-color: #ccf;
		--active-color: orange;
	}
}

<?php } ?>
