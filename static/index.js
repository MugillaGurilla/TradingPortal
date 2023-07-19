/* Alterating scroll speed for the
   History table */
$(document).ready(function() {
    var scrollSpeed = 100;
    var step = 0.1;

    $(".history-table").on("wheel", function(event) {
        event.preventDefault();
        var scrollAmount = event.originalEvent.deltaY  * step;
        $(this).scrollTop($(this).scrollTop() + scrollAmount);

    });
});