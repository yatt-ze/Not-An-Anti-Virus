// Syntax-highlighter and user-agent tables: shell command names joined by `|` (#317).
var bashBuiltins = /\b(?:alias|apt-get|awk|basename|bash|cat|chmod|curl|cut|date|dd|grep|sh|zsh)\b/;
var bots = /(nuhk|curl|Googlebot|Yammybot|Openbot|Slurp|MSNBot)/;
var events = {"tool":["{enum:ls|cd|find|cat|rm|grep|curl|git|python|bash|sh}"]};
var targets = {curl:{key:"curl",title:"cURL",extname:".sh",default:"curl"}, shell:"bash|sh"};
