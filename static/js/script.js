function Showname() {
    var input = document.getElementById("upload-code");
    var path = input.value;
    var filename = "";
    if(path.lastIndexOf("\\") != -1)
        filename = path.substring(path.lastIndexOf("\\") + 1,path.length);
    else
        filename = path.substring(path.lastIndexOf("/") + 1,path.length);
    document.getElementById("log").innerHTML = filename;
};
