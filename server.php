<?php

namespace KD2\WebDAV
{
	/*
		This file is part of KD2FW -- <https://kd2.org/>

		Copyright (c) 2001-2022+ BohwaZ <https://bohwaz.net/>
		All rights reserved.

		KD2FW is free software: you can redistribute it and/or modify
		it under the terms of the GNU Affero General Public License as published by
		the Free Software Foundation, either version 3 of the License, or
		(at your option) any later version.

		KD2FW is distributed in the hope that it will be useful,
		but WITHOUT ANY WARRANTY; without even the implied warranty of
		MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
		GNU Affero General Public License for more details.

		You should have received a copy of the GNU Affero General Public License
		along with KD2FW.  If not, see <https://www.gnu.org/licenses/>.
	*/

	class Exception extends \RuntimeException {}

	/**
	 * This is a minimal, lightweight, and self-supported WebDAV server
	 * it does not require anything out of standard PHP, not even an XML library.
	 * This makes it more secure by design, and also faster and lighter.
	 *
	 * - supports PROPFIND custom properties
	 * - supports HTTP ranges for GET requests
	 * - supports GZIP encoding for GET
	 *
	 * You have to extend the AbstractStorage class and implement all the abstract methods to
	 * get a class-1 and 2 compliant server.
	 *
	 * By default, locking is simulated: nothing is really locked, like
	 * in https://docs.rs/webdav-handler/0.2.0/webdav_handler/fakels/index.html
	 *
	 * You also have to implement the actual storage of properties for
	 * PROPPATCH requests, by extending the 'setProperties' method.
	 * But it's not required for WebDAV file storage, only for CardDAV/CalDAV.
	 *
	 * Differences with SabreDAV and RFC:
	 * - If-Match, If-Range are not implemented
	 *
	 * @author BohwaZ <https://bohwaz.net/>
	 */
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

		// Custom properties
		/**
		 * File MD5 hash
		 * Your implementation should return the hexadecimal encoded MD5 hash of the file
		 */
		const PROP_DIGEST_MD5 = 'urn:karadav:digest_md5';

		/**
		 * Empty value if you want to have the property found and empty, return this constant
		 */
		const EMPTY_PROP_VALUE = 'DAV::empty';

		const SHARED_LOCK = 'shared';
		const EXCLUSIVE_LOCK = 'exclusive';

		/**
		 * Base server URI (eg. "/index.php/webdav/")
		 */
		protected string $base_uri;

		/**
		 * Original URI passed to route() before trim
		 */
		public string $original_uri;

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
			$this->base_uri = rtrim($uri, '/') . '/';
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
					$props = $this->storage->properties(trim($uri . '/' . $file, '/'), self::BASIC_PROPERTIES, 0);
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

			// Support for checksum matching
			// https://dcache.org/old/manuals/UserGuide-6.0/webdav.shtml#checksums
			if (!empty($_SERVER['HTTP_CONTENT_MD5'])) {
				$hash = bin2hex(base64_decode($_SERVER['HTTP_CONTENT_MD5']));
			}

			$this->checkLock($uri);

			if (!empty($_SERVER['HTTP_IF_MATCH'])) {
				$etag = trim($_SERVER['HTTP_IF_MATCH'], '" ');
				$prop = $this->storage->properties($uri, ['DAV::getetag'], 0);

				if (!empty($prop['DAV::getetag']) && $prop['DAV::getetag'] != $etag) {
					throw new Exception('ETag did not match condition', 412);
				}
			}

			// Specific to NextCloud/ownCloud
			$mtime = (int)($_SERVER['HTTP_X_OC_MTIME'] ?? 0) ?: null;

			if ($mtime) {
				header('X-OC-MTime: accepted');
			}

			$created = $this->storage->put($uri, fopen('php://input', 'r'), $hash, $mtime);

			$prop = $this->storage->properties($uri, ['DAV::getetag'], 0);

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
			$requested_props = self::BASIC_PROPERTIES;
			$requested_props[] = 'DAV::getetag';

			// RFC 3230 https://www.rfc-editor.org/rfc/rfc3230.html
			if (!empty($_SERVER['HTTP_WANT_DIGEST'])) {
				$requested_props[] = self::PROP_DIGEST_MD5;
			}

			$props = $this->storage->properties($uri, $requested_props, 0);

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
				throw new \RuntimeException('Invalid file array returned by ::get()');
			}

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
			elseif (isset($_SERVER['HTTP_ACCEPT_ENCODING'])
				&& false !== strpos($_SERVER['HTTP_ACCEPT_ENCODING'], 'gzip')
				// Don't compress already compressed content
				&& !preg_match('/\.(?:mp4|m4a|zip|docx|xlsx|ods|odt|odp|7z|gz|bz2|rar|webm|ogg|mp3|ogm|flac|ogv|mkv|avi)$/i', $uri)) {
				$gzip = true;
				header('Content-Encoding: gzip', true);
			}

			// Try to avoid common issues with output buffering and stuff
			if (function_exists('apache_setenv'))
			{
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
				$gzip = deflate_init(ZLIB_ENCODING_GZIP, ['level' => 9]);

				$fp = fopen('php://memory', 'wb');

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

			while (!feof($file['resource']) && ($end === null || $end > 0)) {
				$l = $end !== null ? min(8192, $end) : 8192;

				echo fread($file['resource'], $l);
				flush();

				if (null !== $end) {
					$end -= 8192;
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
				&& current($this->storage->properties($destination, ['DAV::resourcetype'], 0)) == 'collection') {
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

			$this->storage->mkcol($uri);

			http_response_code(201);
			return null;
		}

		/**
		 * Return a list of requested properties, if any.
		 * We are using regexp as we don't want to depend on a XML module here.
		 * Your are free to re-implement this using a XML parser if you wish
		 */
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
			$properties = $this->storage->properties($uri, $requested_keys, $depth);

			if (null === $properties) {
				throw new Exception('This does not exist', 404);
			}

			$items = [$uri => $properties];

			if ($depth) {
				foreach ($this->storage->list($uri, $requested) as $file => $properties) {
					$path = trim($uri . '/' . $file, '/');
					$properties = $properties ?? $this->storage->properties($path, $requested_keys, 0);

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

				$path = '/' . str_replace('%2F', '/', rawurlencode(trim($this->base_uri . $uri, '/')));

				if (($item['DAV::resourcetype'] ?? null) == 'collection') {
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
			$this->checkLock($uri);

			$body = file_get_contents('php://input');

			$this->storage->setProperties($uri, $body);

			// http_response_code doesn't know the 207 status code
			header('HTTP/1.1 207 Multi-Status', true);
			header('Content-Type: application/xml; charset=utf-8');

			$out = '<?xml version="1.0" encoding="utf-8"?>' . "\n";
			$out .= '<d:multistatus xmlns:d="DAV:">';
			$out .= '</d:multistatus>';

			return $out;
		}

		public function http_lock(string $uri): ?string
		{
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

		/**
		 * Return current lock token supplied by client
		 */
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

		/**
		 * Check if the resource is protected
		 * @throws Exception if the resource is locked
		 */
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
				$etag = current($this->storage->properties($uri, ['DAV::getetag'], 0));

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
			$uri = rtrim($uri, '/');

			if ($uri . '/' == $this->base_uri) {
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
			return $uri;
		}

		public function route(?string $uri = null): bool
		{
			if (null === $uri) {
				$uri = $_SERVER['REQUEST_URI'] ?? '/';
			}

			$this->original_uri = $uri;

			if ($uri . '/' == $this->base_uri) {
				$uri .= '/';
			}

			if (0 === strpos($uri, $this->base_uri)) {
				$uri = substr($uri, strlen($this->base_uri));
			}
			else {
				$this->log('<= %s is not a managed URL', $uri);
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

		/**
		 * Utility function to create HMAC hash of data, useful for NextCloud and WOPI
		 */
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
		/**
		 * Return the requested resource
		 *
		 * @param  string $uri Path to resource
		 * @return null|array An array containing one of those keys:
		 * path => Full filesystem path to a local file, it will be streamed directly to the client
		 * resource => a PHP resource (eg. returned by fopen) that will be streamed directly to the client
		 * content => a string that will be returned
		 * or NULL if the resource cannot be returned (404)
		 *
		 * It is recommended to use X-SendFile inside this method to make things faster.
		 * @see https://tn123.org/mod_xsendfile/
		 */
		abstract public function get(string $uri): ?array;

		/**
		 * Return TRUE if the requested resource exists, or FALSE
		 *
		 * @param  string $uri
		 * @return bool
		 */
		abstract public function exists(string $uri): bool;

		/**
		 * Return the requested resource properties
		 *
		 * This method is used for HEAD requests, for PROPFIND, and other places
		 *
		 * @param string $uri Path to resource
		 * @param null|array $requested_properties Properties requested by the client, NULL if all available properties are requested,
		 * or if specific properties are requested, each item will be a key,
		 * like 'namespace_url:property_name', eg. 'DAV::getcontentlength' or 'http://owncloud.org/ns:size'
		 * See Server::BASIC_PROPERTIES for default properties.
		 * @param int $depth Depth, can be 0 or 1
		 * @return null|array An array containing the requested properties, each item must have a key
		 * of the same form as the requested properties.
		 *
		 * This method MUST return NULL if the resource does not exist.
		 * Or it MUST return an array, where the keys are 'namespace_url:property_name' tuples,
		 * and the value is the content of the property tag.
		 */
		abstract public function properties(string $uri, ?array $requested_properties, int $depth): ?array;

		/**
		 * Store resource properties
		 * @param string $uri
		 * @param string $body XML PROPPATCH request, parsing it is up to you
		 */
		public function setProperties(string $uri, string $body): void
		{
			// By default, properties are not saved
		}

		/**
		 * Create or replace a resource
		 * @param  string $uri     Path to resource
		 * @param  resource $pointer A PHP file resource containing the sent data (note that this might not always be seekable)
		 * @param  null|string $hash A MD5 hash of the resource to store, if it is supplied,
		 * this method should fail with a 400 code WebDAV exception and not proceed to store the resource.
		 * @param  null|int $mtime The modification timestamp to set on the file
		 * @return bool Return TRUE if the resource has been created, or FALSE it has just been updated.
		 */
		abstract public function put(string $uri, $pointer, ?string $hash, ?int $mtime): bool;

		/**
		 * Delete a resource
		 * @param  string $uri
		 * @return void
		 */
		abstract public function delete(string $uri): void;

		/**
		 * Copy a resource from $uri to $destination
		 * @param  string $uri
		 * @param  string $destination
		 * @return bool TRUE if the destination has been overwritten
		 */
		abstract public function copy(string $uri, string $destination): bool;

		/**
		 * Move (rename) a resource from $uri to $destination
		 * @param  string $uri
		 * @param  string $destination
		 * @return bool TRUE if the destination has been overwritten
		 */
		abstract public function move(string $uri, string $destination): bool;

		/**
		 * Create collection of resources (eg. a directory)
		 * @param  string $uri
		 * @return void
		 */
		abstract public function mkcol(string $uri): void;

		/**
		 * Return a list of resources for target $uri
		 *
		 * @param  string $uri
		 * @param  array $properties List of properties requested by client (see ::properties)
		 * @return iterable An array or other iterable (eg. a generator)
		 * where each item has a key string containing the name of the resource (eg. file name),
		 * and the value being an array of properties, or NULL.
		 *
		 * If the array value IS NULL, then a subsequent call to properties() will be issued for each element.
		 */
		abstract public function list(string $uri, array $properties): iterable;

		/**
		 * Lock the requested resource
		 * @param  string $uri   Requested resource
		 * @param  string $token Unique token given to the client for this resource
		 * @param  string $scope Locking scope, either ::SHARED_LOCK or ::EXCLUSIVE_LOCK constant
		 * @return void
		 */
		public function lock(string $uri, string $token, string $scope): void
		{
			// By default locking is not implemented
		}

		/**
		 * Unlock the requested resource
		 * @param  string $uri   Requested resource
		 * @param  string $token Unique token sent by the client
		 * @return void
		 */
		public function unlock(string $uri, string $token): void
		{
			// By default locking is not implemented
		}

		/**
		 * If $token is supplied, this method MUST return ::SHARED_LOCK or ::EXCLUSIVE_LOCK
		 * if the resource is locked with this token. If the resource is unlocked, or if it is
		 * locked with another token, it MUST return NULL.
		 *
		 * If $token is left NULL, then this method must return ::EXCLUSIVE_LOCK if there is any
		 * exclusive lock on the resource. If there are no exclusive locks, but one or more
		 * shared locks, it MUST return ::SHARED_LOCK. If the resource has no lock, it MUST
		 * return NULL.
		 *
		 * @param  string      $uri
		 * @param  string|null $token
		 * @return string|null
		 */
		public function getLock(string $uri, ?string $token = null): ?string
		{
			// By default locking is not implemented, so NULL is always returned
			return null;
		}
	}
}

namespace NanoKaraDAV
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

		public function list(string $uri, ?array $properties): iterable
		{
			$dirs = glob($this->path . $uri . '/*', \GLOB_ONLYDIR);
			$dirs = array_map('basename', $dirs);
			natcasesort($dirs);

			$files = glob($this->path . $uri . '/*');
			$files = array_map('basename', $files);
			$files = array_diff($files, $dirs);

			// Remove PHP files from listings
			$files = array_filter($files, fn($a) => !preg_match('/\.(?:php\d?|phtml|phps)$/i', $a));

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
					return new \DateTime('@' . filemtime($target));
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
			$target = $this->path . $uri;

			if (!file_exists($target)) {
				throw new WebDAV_Exception('Target does not exist', 404);
			}

			if (is_dir($target)) {
				foreach (glob($target . '/*') as $file) {
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
	use NanoKaraDAV\Server;
	use NanoKaraDAV\Storage;

	$uri = strtok($_SERVER['REQUEST_URI'], '?');
	$root = substr(__DIR__, strlen($_SERVER['DOCUMENT_ROOT']));

	if (false !== strpos($uri, '..')) {
		http_response_code(404);
		die('Invalid URL');
	}

	$relative_uri = ltrim(substr($uri, strlen($root)), '/');

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
