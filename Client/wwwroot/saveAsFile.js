function saveAsFile(fileName, byteBase64) {
    var link = document.createElement('a');
    link.download = fileName;
    //link.href = 'data:application/vnd.openxmlformats-pfficedocument.spreadsheetml.sheet;base64,' + byteBase64;
    link.href = "data:application/octet-stream;base64," + bytesBase64;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}