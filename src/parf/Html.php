<?

/*

 * XSS-free HTML generation library

 * inspired by Banana-Html (https://github.com/nazar-pc/BananaHTML)

 * PHP 5.6+

TODO:

  * [+] spartan test
  * [-] composer package - parf/Html

  * JS escape in JS elements (find right way)

  * H::url

  * ATTRIBUTES
    * javascript
    * allow as-is

  * make sure
    we pass all cases from there:
    https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
    - tofix: <IMG SRC="jav&#x0A;ascript:alert('XSS');">, perl -e 'print "<IMG SRC=java\0script:alert(\"XSS\")>";' > out
            <IMG SRC='vbscript:msgbox("XSS")'>
    - tofix: - JS inside Attributes
      src, dynsrc, lowsrc, background
    - tofix: style element <STYLE>li {list-style-image: url("javascript:alert('XSS')");}</STYLE>
    - <BR SIZE="&{alert('XSS')}">
    - <IMG STYLE="xss:expr/*XSS* /ession(alert('XSS'))" >

  Ex:

  use parf\Html as H;

    > H::div("div 1", "div #2 content", "div3: auto-escaping", ["div4", "attr" => "value", "class" => "my-class"]);
    <div>div 1</div>
    <div>div #2 content</div>
    <div>div3: auto-escaping</div>
    <div attr="value" class="my-class">div4</div>

    // Using Array of Elements
    $a = [1,2,3];
    H::div(...$a);   // draw three divs


    // css/xpath alike syntax
    H::{"div#id1.class-1 span#id2.class-2.class-3 div[my-attr=test].x"}(1,2,3)
    <div id="id1" class="class-1">
      <span id="id2" class="class-2 class-3">
        <div my-attr="test" class="x">1</div>
        <div my-attr="test" class="x">2</div>
        <div my-attr="test" class="x">3</div>
      </span>
    </div>

    // Another example
    H::{'a#github.cool-link.two-classes[href=https://github.com/parf/spartan-test#hash][title=Spartan Test]'}(['GitHub', 'attr' => 'yes'] );

    > H::{"div.c1 span.c2 div.c3 span.c4"}(1,2,3)
    <div class="c1">
      <span class="c2">
        <div class="c3">
          <span class="c4">1</span>
          <span class="c4">2</span>
          <span class="c4">3</span>
        </div>
      </span>
    </div>

    // "|" extension - delimit wrapper part and repeating part
    > H::{"div.c1 span.c2 | div.c3 span.c4"}(1,2,3)
    <div class="c1"><span class="c2">
      <div class="c3"><span class="c4">1</span></div>
      <div class="c3"><span class="c4">2</span></div>
      <div class="c3"><span class="c4">3</span></div>
    </span></div>

    > H::{'ul.unordered-list | li span'}('one', 'two', 'three');
    <ul class="unordered-list">
      <li><span>one</span></li>
      <li><span>two</span></li>
      <li><span>three</span></li>
    </ul>

    // * href as array [0=>url, "key" => value", "#" => 'hash' )
    If attribute value is an array - it considered a url
    H::a(["text", "href" => ["//site.com", "page" => "page one", "xx" => "<>"]]);
    <a href="//site.com?page=page+one&xx=%3C%3E">text</a>


    // Extensions:

    TABLE($table_attrs, array $header, array $rows)
    // H::table("#table1.my_class", ["one", "two", "three"],[[[1, "class" => "td-class"],2,3],[4,5,6]])

    TRS(array $header, array-of-arrays $rows)
    // H::trs(["one", "two", "three"],[[[1, "class" => "td-class"], 2, 3], [-1=>".selected", 4, 5, 6]])

    SELECT($name_or_attrs, array $name2display, $selected=false)
    // H::select("my-select.my-class", [1 => 'one', 2 => 'two', 3 => 'three'], 2);

    CHECKBOX($name_or_attrs, array $value2text, array $checked=[], $template = " %s<br>")
    // H::checkbox("my-check.class", ["bike" => "i have a Bike", "car" => "I have a car"], ['car' => 1, 'bike' =>1])

    RADIO($name_or_attrs, array $value2text, $checked=false, $template = " %s<br>")
    // H::radio("sex.class", ["male" => "Male", "female" => "Female"], "male")

    INPUT_TEXT($name_or_attrs, $value)
    // H::input_text("name", "Parf")  ,  H::input_text("name.class#id", ["Parf", "disabled" => ""])

 */

namespace parf;

class Html {

    // http://stackoverflow.com/questions/3741896/what-do-you-call-tags-that-need-no-ending-tag
    // http://stackoverflow.com/questions/3558119/are-self-closing-tags-valid-in-html5
    static $NO_END_TAG = ['area' => 1, 'link' => 1, 'meta' => 1, 'input' => 1,
                          'hr' => 1, 'img' => 1, 'br' => 1, 'wbr' => 1,
                          'command' => 1, 'embed' => 1, 'param' => 1, 'source' => 1, 'track' => 1,
                          'button' => 1, "col" => 1, "base" => 1];


    // table attrs - id and class or any other table attributes
    // Ex: H::table("#table1.my_class", ["one", "two", "three"],[[[1, "class" => "td-class"],2,3],[4,5,6]])
    PUBLIC static function table(/*string|array*/ $table_attrs, array $header, array $rows) { # html
        list($x, $table_attrs) = static::_attr($table_attrs);
        return static::_t("table", [2 => static::trs($header, $rows)] + $table_attrs);
    }

    // header - array of headers
    // rows   - array of array  (element -1 contains tr attributes)
    // Ex:  H::trs(["one", "two", "three"],[[[1, "class" => "td-class"], 2, 3], [-1=>".selected", 4, 5, 6]])
    PUBLIC static function trs(array $header, array $rows) { # html
        $h = [];
        if ($header)
            $h[] = static::{"tr th"}(...$header);
        foreach ($rows as $row) {
            if (! isset($row[-1])) {
                $h[] = static::{"tr td"}(...$row);
                continue;
            }
            // we have TR attributes
            list($x, $tr_attr) = static::_attr($row[-1]);
            unset($row[-1]);
            $tds = static::td(...$row);
            $h[] = static::tr([2 => $tds]+$tr_attr);
        }
        return join("\n", $h);
    }

    // $name_or_attrs : "name.class#id" or hash with select attrs
    // $name2display  : [name => display]
    // $selected      : $name || [$name => 1]
    // Ex:
    //   H::select("my-select.my-class", [1 => 'one', 2 => 'two', 3 => 'three'], 2);
    //   H::select(['name' => "my-select", 'style' => '..'], [1 => 'one', 2 => 'two', 3 => 'three'], 2);
    PUBLIC static function select($name_or_attrs, array $name2display, $selected=false) { # html
        $r = [];
        foreach ($name2display as $v => $d) {
            $z = [$d, "value" => $v];
            if (is_array($selected)) {
                if ($selected[$v])
                    $z['selected'] = "";  // multiple select case
            } elseif ($v == $selected)
                $z['selected'] = "";
            $r[] = $z;
        }
        list($name, $attr) = static::_attr($name_or_attrs);
        if ($name)
            $attr["name"] = $name;
        return static::_t("select", [2 => static::option(...$r)]+$attr);
    }

    // <input type=checkbox name=$name value=$value checked>$text<br>
    // Ex: H::checkbox("my-check.class", ["bike" => "i have a Bike", "car" => "I have a car"], ['car' => 1, 'bike' =>1])
    PUBLIC static function checkbox($name_or_attrs, array $value2text, array $checked=[], $template = " %s<br>") { # html
        list($name, $attr) = static::_attr($name_or_attrs);
        if ($name)
            $attr["name"] = $name;
        $attr['type'] = "checkbox";
        $r = [];
        foreach ($value2text as $v => $t) {
            $z = $attr + [1 => sprintf($template, $t), "value" => $v];
            if (@$checked[$v])
                $z["checked"] = "";
            $r[] = $z;
        }
        return static::input(...$r);
    }

    // <input type="radio" name="sex" value="male" checked>Male<br>
    // Ex: H::radio("sex.class", ["male" => "Male", "female" => "Female"], "male")
    PUBLIC static function radio($name_or_attrs, array $value2text, $checked=false, $template = " %s<br>") { # html
        list($name, $attr) = static::_attr($name_or_attrs);
        if ($name)
            $attr["name"] = $name;
        $attr['type'] = "radio";
        $r = [];
        foreach ($value2text as $v => $t) {
            $z = $attr + [1 => sprintf($template, $t), "value" => $v];
            if ($checked == $v)
                $z["checked"] = "";
            $r[] = $z;
        }
        return static::input(...$r);
    }

    // input type=text value=$value
    // $value is (string)"value" or ["value", attr=>x, ...]
    // Ex: H::input_text("name", $name)
    PUBLIC static function input_text($name_or_attrs, $value) { # html
        list($name, $attr2) = static::_attr($name_or_attrs);
        if (is_array($value)) {
            $attr = $value;
            if ($attr[0]) {
                $attr['value'] = $attr[0];
                unset($attr[0]);
            }
        } else
            $attr = ['value' => $value];
        if ($name)
            $attr["name"] = $name;
        return static::input($attr+$attr2);
    }

    // convert string attr to hash of attr
    // if attr is already hash - it is untouched
    // supported expansions: "#id.class1.class2[attr=val]"
    // Ex: H::_attr("tag#id.class1.class2[attr=val][attr2=val2]")
    static function _attr($tag_attrs) { # [$tag, ["attr" => "value"]]
        if (is_array($tag_attrs))
            return ["", $tag_attrs];  // already parsed
        $attrs = [];
        $ta = preg_split("!([#\.\|\[])!", $tag_attrs, -1, PREG_SPLIT_DELIM_CAPTURE);
        $tag = array_shift($ta);
        foreach (range(0, \count($ta), 2) as $p) {
            $a = @$ta[$p+1];
            switch (@$ta[$p]) {
                case '#':
                    if (! isset($attrs['id']))
                        $attrs['id'] = $a;
                    break;
                case '.':
                    if (isset($attrs['class']))
                        $attrs['class'] .= " ".$a;
                    else
                        $attrs['class'] = $a;
                    break;
                case '[':
                    $a = static::_bracket_unescape($a); // square brackets inside are escaped
                    list($a, $v) = explode("=", substr($a, 0, -1), 2);
                    if (! isset($attrs[$a]))
                        $attrs[$a] = $v;
                    break;
            }
        }
        return [$tag, $attrs];
    }

    // $url_args is [0=>"url", 1=>"unescaped-url", "arg" => $value, .., '#' => $hash]
    // url is escaped
    // arg-names and arg-values are escaped
    // Ex: H::url(["/page/?arg1=abc", 'arg2' => 'val', '#' => 'abc'])
    // Ex: H::url(["//site.com/page?arg1<script>=<script>", 'arg2' => 'val', "<script>" => "<script>!-&?="])
    // Ex: H::url([" JaVaScript: "])
    static function url(array $url_args) { # "url"
        $url = "";
        $hash = "";
        if (isset($url_args[0])) { # escape inner text
            $url = trim(htmlspecialchars($url_args[0], ENT_QUOTES));
            if (strtolower(substr($url, 0, 11)) == 'javascript:')
                throw new \InvalidArgumentException("javascript in protected argument");
            unset($url_args[0]);
        }
        if (isset($url_args[1])) { # NO Escaping for $url
            $url = $url_args[1];
            unset($url_args[1]);
        }
        if (isset($url_args['#'])) { # HASH
            $hash = "#".trim(htmlspecialchars($url_args['#'], ENT_QUOTES));
            unset($url_args['#']);
        }
        $delimiter = strpos($url, "?") !== false ? "&" : "?";
        $r = [];
        foreach ($url_args as $a => $v)
            $r[] = urlencode($a)."=".urlencode($v);
        return $r ? $url.$delimiter.join("&", $r).$hash : $url.$hash;
    }


    // internal
    // $tag - xml tag + xpath/css/custom extension
    // $attrs - [0 => "text", 1 => "html", "2" => "html-for-ident", $attr" => "unescaped-value"]
    static function _t($tag, $attrs=[]) { # html
        $tag = trim($tag);
        $text = "";
        if (! is_array($attrs))
            $attrs = [$attrs];

        // "tag tag tag"
        if (strpos($tag, ' ')) {
            list($t1, $t2) = explode(" ", $tag, 2);
            return static::_t($t1, [1=> static::_t($t2, $attrs)]);
        }

        // tag is tag+css/xpath
        if (preg_match("![#\.\[]!", $tag)) {
            list($tag, $attrs2) = static::_attr($tag);
            $attrs += $attrs2;
        }

        // xml tag case
        $otag = $tag;
        if (isset($attrs[0])) { # escape inner text
            $text = htmlspecialchars($attrs[0], ENT_QUOTES);
            unset($attrs[0]);
        }
        if (isset($attrs[1])) { # no escaping case
            if ($text)
                throw new \InvalidArgumentException("cant combine 0=>`text` and 1=>`html`");
            $text = $attrs[1];
            unset($attrs[1]);
        }
        if (isset($attrs[2])) { # no escaping case + ident by 2 spaces
            if ($text)
                throw new \InvalidArgumentException("cant combine 0=>`text` and 2=>`html`");
            $text = "\n  ".str_replace("\n", "\n  ", $attrs[2])."\n";
            unset($attrs[2]);
        }

        if ($attrs) {
            $h = [];
            foreach ($attrs as $a => $v) {
                if (is_array($v)) { // URL case
                    $h[] = htmlspecialchars($a, ENT_QUOTES)."=\"".self::url($v)."\"";
                    continue;
                }
                if ($a == 'onclick') {
                    $h[] = "$a=\"".str_replace("\"", "&quot;", $v)."\"";
                    continue;
                }
                if ($v)
                    $h[]=htmlspecialchars($a, ENT_QUOTES)."=\"".htmlspecialchars($v, ENT_QUOTES)."\"";
                else {
                    if ($v !== false)
                        $h[]=htmlspecialchars($a, ENT_QUOTES);
                }
            }
            $otag .= " ".join(" ", $h);
        }

        if (@static::$NO_END_TAG[$tag])
            return "<$otag>$text";

        return "<$otag>$text</$tag>";
    }

    // internal
    // escaping inside square brackets - used in __CallStatic preg_replace_callback
    // Ex: H::{"a[href=https://site.com/page#hash][class=class1 class2]"}("text")
    /* protected */ static function _bracket_escape(array $t01) { # escaped text
        // [0] full match, [1] - inside brackets match
        return strtr($t01[0], [' ' => "\e1", '.' => "\e2", '#' => "\e3", '|' => "\e4"]);
    }

    // internal
    // opposite of inside square brackets escaping
    /* protected */ static function _bracket_unescape($text) { # original text
        return strtr($text, ["\e1" => ' ', "\e2" => ".", "\e3" => '#', "\e4" => '|']);
    }

    // Form1: $tag($text)
    //        $tag(text, text, text)
    //        $tag(...[text, text,text])        // php 5.6 variadic syntax
    // Form2: $tag([text, 'attr' => value], [], ...)
    // Form3: $tag([1 => $non-escaped-html, 'attr' => value], [], ...)
    //
    // Url builder: when attr-value is an array it is considered a url: [$base, "arg" => $value, ...] and is encoded using
    // "onclick" attribute - only "\"" are escaped right way
    //
    // Ex:
    //    H::a("text", ["text", 'href' => ['http://site.com/', 'page' => 10], "class" => "alert"], [1=>'<p>no-escaping</p>', "name" => "a"])
    static function __callStatic($tag, array $args) { # html

        if (strpos($tag, '[') !== false) {
            $tag = preg_replace_callback("!\[(.*?)\]!", "static::_bracket_escape", $tag);
        }

        if (strpos($tag, '|') !== false) {
            list($t1, $t2) = explode("|", $tag, 2);
            $t1 = trim($t1);
            $t2 = trim($t2);
            $r = [];
            foreach ($args as $a)
                $r[] = static::_t($t2, $a);
            if (! $t1)
                return join("\n", $r);
            return static::_t($t1, [2 => join("\n", $r)]);
        }

        if (strpos($tag, ' ')) {
            list($t1, $t2) = explode(" ", $tag, 2);
            $in = static::__callStatic($t2, $args);
            return static::_t($t1, [2 => $in]);
        }

        if (! $args)
            return static::_t($tag)."\n";

        if (count($args) == 1)
            return static::_t($tag, $args[0]);

        $r = [];
        foreach ($args as $a)
            $r[] = static::_t($tag, $a);
        return join("\n", $r);

    }

}

/*

TEST:

H::a("text", ["text", 'href' => 'http://site.com/?q=123', "class" => "a z"], ["name" => "a"], [1=>'<p>no-escaping</p>']);

H::url(["//comfi.com?page=a", "name" => "\<>!-&?"])

> H::{'div#id.class1.class2 span#id.cl1.cl2'}(["text", 'tag' => 'val'], "two", ["three", 'id' => 'new-id'])
<div id="id" class="class1 class2">
  <span tag="val" id="id" class="cl1 cl2">text</span>
  <span id="id" class="cl1 cl2">two</span>
  <span id="new-id" class="cl1 cl2">three</span>
</div>

> H::{'div.form-class form[action=/url] | div.input_line input[type=text]'}(["value" => "text", 'tag' => 'val'], ["name" => "b", "value" => "two"], ["value" => "sumit", 'id' => 'new-id', 'type' => "submit"], ['disabled' => '', 'type' => false])
<div class="form-class"><form action="/url">
  <div class="input_line"><input value="text" tag="val" type="text"></div>
  <div class="input_line"><input name="b" value="two" type="text"></div>
  <div class="input_line"><input value="sumit" id="new-id" type="submit"></div>
  <div class="input_line"><input disabled></div>
</form></div>


H::{'tr th'}("one", "two", "three")

*/

