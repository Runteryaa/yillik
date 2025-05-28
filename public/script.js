document.addEventListener('DOMContentLoaded', function() {
    if (!localStorage.getItem('isVisited')) {
        var infoDiv = document.getElementById('first-visit');
        if (infoDiv) {
            infoDiv.style.display = 'unset';
        }
        localStorage.setItem('isVisited', 'true');
    }
});

closeFirstVisit = function() {
    var infoDiv = document.getElementById('first-visit');
    if (infoDiv) {
        infoDiv.style.display = 'none';
    }
}

function copy(id) {
  var copyText = id
  copyText.select();
  copyText.setSelectionRange(0, 99999);
  navigator.clipboard.writeText(copyText.value);
  alert("Copied the text: " + copyText.value);
}