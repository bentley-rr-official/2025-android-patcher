'use strict';
// Reads every static String field of the given PairIP "holder" classes from the running,
// UNMODIFIED Rec Room process (where PairIP's startup program has already filled them in).
// Driven by scripts/dump_holders.py via RPC:  exports.dump(["a.b.Holder", ...])
//
// Needs Frida 16.x (Frida 17 no longer bundles the Java bridge in plain scripts).

// Strings are returned as pure-ASCII JSON-string bodies (every non-printable-ASCII UTF-16 code
// unit, plus '"' and '\', becomes \uXXXX) so lone surrogates etc. survive the RPC transport.
function esc(s) {
  var out = '';
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c >= 0x20 && c < 0x7f && c !== 0x22 && c !== 0x5c) {
      out += s.charAt(i);
    } else {
      out += '\\u' + ('0000' + c.toString(16)).slice(-4);
    }
  }
  return out;
}

rpc.exports = {
  dump: function (classNames) {
    if (typeof Java === 'undefined') {
      throw new Error('No Java bridge in this Frida runtime. Use Frida 16.x ' +
                      '(pip install frida==16.7.19 frida-tools==13.7.1) and a matching frida-server.');
    }
    if (!Java.available) {
      throw new Error('Java VM not available in the target process yet.');
    }
    var result = { meta: {}, holders: {}, errors: {} };

    Java.performNow(function () {
      var Modifier = Java.use('java.lang.reflect.Modifier');

      try {
        var app = Java.use('android.app.ActivityThread').currentApplication();
        var pkg = app.getPackageName();
        var pi = app.getPackageManager().getPackageInfo(pkg, 0);
        result.meta.package = String(pkg);
        result.meta.versionCode = pi.versionCode.value;
        result.meta.versionName = String(pi.versionName.value);
        var inst = app.getPackageManager().getInstallerPackageName(pkg);
        result.meta.installer = inst === null ? null : String(inst);
      } catch (e) {
        result.meta.error = String(e);
      }

      classNames.forEach(function (name) {
        try {
          var K = Java.use(name);
          var fields = K.class.getDeclaredFields();
          var map = {};
          for (var i = 0; i < fields.length; i++) {
            var f = fields[i];
            if (!Modifier.isStatic(f.getModifiers())) continue;
            if (String(f.getType().getName()) !== 'java.lang.String') continue;
            f.setAccessible(true);
            var v = f.get(null);
            map[String(f.getName())] = (v === null) ? null : esc(v.toString());
          }
          result.holders[name] = map;
        } catch (e) {
          result.errors[name] = String(e);
        }
      });
    });
    return result;
  }
};
