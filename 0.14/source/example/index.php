<?php

function myDie($tekst) {
  echo <<< EOF
  <p style="color:red; display:inline;">${tekst}</p>
  </body>
  </html>
EOF;
  exit();
}
if(!defined('INCLUDE_CHECK')) define('INCLUDE_CHECK', true);
require 'dbconnect.php';

?>
<!DOCTYPE html>
<html lang="en-us">
<head>
<title>openGalaxy Management System</title>

<?php

// Get settings from database and load the correct JQuery UI theme

$result = @$dbLink->query("SELECT * FROM `GMS Settings`");
if( $result != FALSE ) $GMS_Settings = @$result->fetch_array();
else myDie(@mysqli_error($dbLink));

$htmlOutput   = array();
$htmlOutput[] = '<link rel="stylesheet" href="//ajax.googleapis.com/ajax/libs/jqueryui/1.10.4/themes/'.$GMS_Settings['jqui_theme'].'/jquery-ui.css" />'."\n";
$htmlOutput[] = '<script src="//ajax.googleapis.com/ajax/libs/jquery/1.11.0/jquery.min.js"></script>'."\n";
$htmlOutput[] = '<script src="//ajax.googleapis.com/ajax/libs/jqueryui/1.10.4/jquery-ui.min.js"></script>'."\n";
  
echo implode('',$htmlOutput);
?>

<script src="gms.js?v1"></script>
<link rel="stylesheet" type="text/css" href="gms.css?v1" media="screen" />

</head>
<body id="bodyGMS">


<div id="GMS-Settings-Dialog" title="Settings">
<span style="white-space:nowrap;">
Theme: 
<select id="jqui_theme">
<?php

$theme = array();
$result = @$dbLink->query("SELECT * FROM `jqui_themes`");
if( $result != FALSE ) {
 while ($theme = @$result->fetch_array()) {
  $selected = ( strcmp ( $theme['jqui_theme'], $GMS_Settings['jqui_theme']) == 0 ) ? ' selected' : '';
  echo '<option value="'.$theme['jqui_theme'].'"'.$selected.'>'.$theme['jqui_theme'].'</option>'."\n";
 }
}
else myDie(@mysqli_error($dbLink));

?>
</select>
</span>
</div>

<div id="GMS-Pending-Alarms-Dialog" title="Pending Alarm Messages">
 <div class="GMS-Pending-Alarms-Dialog-outer_div">
  <table class="GMS-Pending-Alarms-Dialog-outer_table">
   <thead>
    <tr class="ui-state-default">
     <th style="display:none;">ID</th>
     <th class="GMS-Pending-Alarms-Dialog-th1">DateTime</th>
     <th class="GMS-Pending-Alarms-Dialog-th2">AccountID</th>
     <th class="GMS-Pending-Alarms-Dialog-th3">Code</th>
     <th class="GMS-Pending-Alarms-Dialog-th4">Name</th>
     <th class="GMS-Pending-Alarms-Dialog-th5">ASCII</th>
     <th class="GMS-Pending-Alarms-Dialog-th6">Description</th>
     <th class="GMS-Pending-Alarms-Dialog-th7">Type</th>
     <th class="GMS-Pending-Alarms-Dialog-th8">Address</th>
     <th class="GMS-Pending-Alarms-Dialog-th9">User</th>
     <th class="GMS-Pending-Alarms-Dialog-th10">Area</th>
     <th class="GMS-Pending-Alarms-Dialog-th11">Peripheral</th>
     <th id="x-filler" class="GMS-Pending-Alarms-Dialog-th_x_filler"></th>
    </tr>
   <thead>
   <tbody>
    <tr>
     <td colspan="12">
      <div id="GMS-Pending-Alarms-Dialog-inner_div" class="GMS-Pending-Alarms-Dialog-inner_div">
       <table id="GMS-Pending-Alarms-Table" class="GMS-Pending-Alarms-Dialog-inner_table">
        <tbody id="GMS-Pending-Alarms-Table-Body">
         <!-- filled via ajax -->
        </tbody>
       </table>
      </div>
     </td>
    </tr>
   </tbody>
  </table>
 </div>
</div>

<!-- dialog for error messages on this page -->
<div id="GMS-Error-Dialog" class="no-padding no-margin">
 <div id="GMS-Error-Dialog-inner" class="no-margin no-border no-padding ui-corner-all"></div>
</div>

</body>
</html>

