<script type="text/javascript">
        function toggle(divId) {
            var divObj = document.getElementById(divId);
            if (divObj) {
                var displayType = divObj.style.display;
                if (displayType == "" || displayType == "block") {
                    divObj.style.display = "none";
                } else {
                    divObj.style.display = "block";
                }
            }
        }
</script>
