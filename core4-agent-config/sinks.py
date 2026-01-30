#!/usr/bin/env python3
"""Sinks module: defines KNOWN_SINKS for each language."""
from typing import Dict, Set

KNOWN_SINKS: Dict[str, Set[str]] = {
    "python": {
        # Existing sinks
        "exec", "eval", "compile", "open", "execfile", "input", "__import__",
        "os.system", "os.popen", "os.spawn",
        "subprocess.Popen", "subprocess.call", "subprocess.run",
        "pickle.loads", "yaml.load", "marshal.load", "shelve.open",
        "sqlite3.connect", "cursor.execute",
        "flask.render_template_string",
        # Added from regex
        "subprocess.check_output", "commands.getoutput",
        "pickle.load", "marshal.loads",
        "cursor.executemany", "cursor.executescript",
        "jinja2.Template", "mako.template",
        "urllib.request.urlopen", "requests.get", "requests.post",
        "xml.etree.ElementTree.parse", "lxml.etree.fromstring",
        "shutil.rmtree", "os.remove",
        "zipfile.ZipFile.extractall", "tarfile.TarFile.extractall",
        "flask.redirect", "django.shortcuts.redirect",
        "re.compile", "re.search",
        # String formatting methods
        "str.format", "format", "str.join", "join",
    },
    "javascript": {
        # Existing sinks
        "eval", "Function", "setTimeout", "setInterval",
        "child_process.exec", "child_process.spawn", "child_process.execFile",
        "document.write", "document.writeln",
        "innerHTML", "outerHTML", "dangerouslySetInnerHTML",
        # Added from regex
        "child_process.execSync", "child_process.spawnSync",
        "vm.runInNewContext", "vm.runInThisContext",
        "db.query", "connection.query", "sequelize.query", # SQLi
        "res.render", "ejs.render", "pug.render", # SSTI
        "JSON.parse", "deserialize", "node-serialize.unserialize", # Deserialization
        "http.request", "axios.get", "request", # SSRF
        "fs.writeFile", "fs.unlink", # File System
        "res.redirect", "window.location.href", # Open Redirect
        "new RegExp", "RegExp", # ReDoS
        # String formatting methods
        "String.prototype.concat", "Array.prototype.join",
    },
    # typescript & tsx share a lot with javascript
    "typescript": {
        "eval", "Function", "setTimeout", "setInterval",
        "child_process.exec", "child_process.spawn", "child_process.execFile",
        "document.write", "document.writeln",
        "innerHTML", "outerHTML", "dangerouslySetInnerHTML",
        "child_process.execSync", "child_process.spawnSync",
        "vm.runInNewContext",
        "db.query", "connection.query",
        "res.render",
        "JSON.parse",
        "http.request", "axios.get",
        "fs.writeFile",
        "res.redirect",
        "new RegExp",
        # String formatting methods
        "String.prototype.concat", "Array.prototype.join",
    },
    "tsx": {
        "eval", "Function", "setTimeout", "setInterval",
        "child_process.exec", "child_process.spawn", "child_process.execFile",
        "document.write", "document.writeln",
        "innerHTML", "outerHTML", "dangerouslySetInnerHTML",
        "child_process.execSync",
        "db.query",
        "res.render",
        "http.request", "axios.get",
        "res.redirect",
        "new RegExp",
        # String formatting methods
        "String.prototype.concat", "Array.prototype.join",
    },
    "java": {
        # Existing sinks
        "Runtime.exec", "ProcessBuilder.start",
        "Statement.execute", "Statement.executeQuery",
        "PreparedStatement.execute", "PreparedStatement.executeQuery",
        # Added from regex
        "Runtime.getRuntime().exec", "ProcessBuilder",
        "ScriptEngine.eval", "Method.invoke", "Class.forName",
        "EntityManager.createQuery", "JdbcTemplate.query", # SQLi
        "ObjectInputStream.readObject", "XMLDecoder.readObject", "new XMLDecoder", # Deserialization
        "XPathExpression.compile", "DocumentBuilderFactory.newInstance", # XXE
        "URL.openConnection", "HttpURLConnection", "RestTemplate.getForObject", # SSRF
        "Files.write", "File.delete", # File system
        "response.sendRedirect", "new RedirectView", # Open Redirect
        "Pattern.compile", "String.matches", # ReDoS
        # String formatting methods
        "String.format", "StringBuilder.append", "StringBuilder.toString",
    },
    "php": {
        # Existing sinks and user requests
        "exec", "system", "passthru", "shell_exec", "eval", "popen", "proc_open", "mysqli_query",
        "require", "require_once", "include", "include_once", "file_get_contents",
        # Added from regex
        "pcntl_exec", "assert", "create_function", "preg_replace", # Code Execution
        "mysql_query", "pg_query", "PDO->query", "PDO->prepare", # SQLi
        "unserialize", "igbinary_unserialize", # Deserialization
        "simplexml_load_string", "DOMDocument->loadXML", # XXE
        "curl_exec", "fsockopen", # SSRF
        "unlink", "rmdir", "move_uploaded_file", # File System
        "header", # Open Redirect
        "sleep", "usleep", # DoS
        "preg_match", # ReDoS
        # String formatting methods
        "sprintf", "vsprintf", "printf", "vprintf",
    },
    "go": {
        # Existing sinks
        "os.StartProcess", "exec.Command", "sql.Query", "sql.Exec", "template.Execute",
        # Added from regex
        "exec.CommandContext", "syscall.Exec", # Command Injection
        "db.Query", "db.Exec", "db.Prepare", # SQLi
        "json.Unmarshal", 
        "xml.Unmarshal", "gob.Decode", # Deserialization
        "template.ExecuteTemplate", "pongo2.FromString", # SSTI
        "xml.NewDecoder", # XXE
        "http.Get", "http.Post", "net.Dial", # SSRF
        "os.Remove", "os.WriteFile", # File System
        "http.Redirect", # Open Redirect
        "fmt.Sprintf", # String formatting
        "strings.Join", # String concatenation
        "regexp.Compile", # ReDoS
    },
    "ruby": {
        # Existing sinks
        "eval", "system", "exec", "syscall", "open", "send", "public_send",
        # Added from regex
        "spawn", "popen", "`", "%x", "instance_eval", "class_eval", # Code Execution
        "find_by_sql", "connection.execute", "where", # SQLi
        "Marshal.load", "YAML.load", "Oj.load", # Deserialization
        "ERB.new", "ERB#result", # SSTI
        "Nokogiri::XML", "REXML::Document.new", # XXE
        "Net::HTTP.get", "URI.open", "RestClient.get", # SSRF
        "File.write", "File.delete", "IO.write", # File System
        "redirect_to", # Open Redirect
        "Regexp.new", # ReDoS
        "sleep", # DoS
        # String formatting methods
        "String#%", "String#format", "Array#join",
    },
    "c_sharp": {
        # Existing sinks (c_sharp -> CSharp)
        "Process.Start", "Assembly.Load", "Type.GetType",
        "SqlCommand.ExecuteReader", "SqlCommand.ExecuteNonQuery",
        # Added from regex
        "ProcessStartInfo", "PowerShell.Invoke", "CodeDomProvider.CompileAssemblyFromSource", # Code Execution
        "OdbcCommand.ExecuteReader", "OleDbCommand.ExecuteNonQuery", # SQLi
        "BinaryFormatter.Deserialize", "JsonConvert.DeserializeObject", "XmlSerializer.Deserialize", # Deserialization
        "XPathNavigator.Evaluate", "XPathDocument.Create", # XPath Injection
        "XmlDocument.Load", "XmlReader.Create", # XXE
        "HttpClient.GetAsync", "WebRequest.Create", # SSRF
        "File.WriteAllText", "Directory.Delete", # File System
        "Response.Redirect", "RedirectToAction", "RedirectPermanent", # Open Redirect
        "new Regex", "Regex.Match", # ReDoS
        # String formatting methods
        "String.Format", "StringBuilder.Append", "StringBuilder.ToString",
    },
    # New languages from regex logs
    "clojure": {
        "clojure.java.shell/sh", "eval", "load-string", "Class/forName",  # Code execution
        "jdbc/query", "jdbc/execute!",  # SQLi
        "ObjectInputStream.", "cheshire.parse-string", # Deserialization
        "selmer/render", "clostache/render", # SSTI
        "clojure.xml/parse", "DocumentBuilderFactory", # XXE
        "http/get", "slurp", # SSRF
        "spit", "clojure.java.io/copy", # File system
        "ring.util.response/redirect", # Open Redirect
        "re-pattern" # ReDoS
    },
    "elixir": {
        "System.cmd", "Port.open", ":os.cmd", "Code.eval_string", # Code execution
        "Ecto.Repo.query", "Ecto.Repo.query!", # SQLi
        ":erlang.binary_to_term", # Deserialization
        "EEx.eval_string", "Mustache.render", # SSTI
        "SweetXml.xpath", ":xmerl_xpath.string", # XPath/XXE
        "HTTPoison.get", "Tesla.get", ":httpc.request", # SSRF
        "File.write", "File.rm", # File system
        "Plug.Conn.redirect", # Open Redirect
        "Regex.compile" # ReDoS
    },
    "erlang": {
        "os:cmd", "open_port", "erl_eval:exprs", # Code execution
        "epgsql:squery", "emysql:execute", # SQLi
        "binary_to_term", # Deserialization
        "erlydtl:render", "mustache:render", # SSTI
        "xmerl_xpath:string", "xmerl_scan:file", # XXE
        "httpc:request", "ibrowse:send_req", # SSRF
        "file:write_file", "file:delete", # File system
        "cowboy_req:reply", # Can be used for open redirect
        "re:compile", "re:run" # ReDoS
    },
    "kotlin": {
        "Runtime.getRuntime().exec", "ProcessBuilder", "ScriptEngineManager",  # Code execution
        "Connection.createStatement", "prepareStatement", "EntityManager.createQuery", # SQLi
        "ObjectInputStream.readObject", "Gson.fromJson", "ObjectMapper.readValue", # Deserialization
        "Thymeleaf", "FreeMarker", "PebbleEngine", # SSTI
        "DocumentBuilderFactory.newInstance", "SAXParserFactory.newInstance", # XXE
        "URL.openConnection", "OkHttpClient.newCall", "RestTemplate", # SSRF
        "File.delete", "Files.write", # File system
        "response.sendRedirect", "RedirectView", # Open Redirect
        "Pattern.compile", "Regex" # ReDoS
    },
    "perl": {
        "system", "exec", "eval", "open", "require", "`", "qx", # Code Execution
        "prepare", "execute", "selectall_arrayref", "DBI->prepare", # SQLi
        "Storable::thaw", "Storable::retrieve", "Data::Dumper::eval", # Deserialization
        "Template->process", "Text::Template->fill_in", # SSTI
        "XML::LibXML", "XML::Parser", # XXE
        "LWP::UserAgent", "HTTP::Tiny", "get", # SSRF
        "unlink", "rename", "print", # File I/O
        "redirect", # Open Redirect
        "qr", "m//" # Regex
    },
    "rust": {
        "std::process::Command::new", "spawn", "output", # Command Injection
        "rusqlite::Connection::execute", "sqlx::query", "diesel::sql_query", # SQLi
        "serde_json::from_str", "bincode::deserialize", # Deserialization
        "tera::Tera::render", "handlebars::Handlebars::render", # SSTI
        "quick_xml::Reader::from_file", "roxmltree::Document::parse", # XXE
        "reqwest::Client::get", "ureq::get", "hyper::Client::request", # SSRF
        "std::fs::write", "std::fs::remove_file", # File System
        "rocket::response::Redirect::to", "warp::redirect", # Open Redirect
        "fancy_regex::Regex::new", "regex::Regex::new" # ReDoS
    },
}
