<?php
/* ===== Настройки ===== */
$NDMC = '/bin/ndmc';
define('DRY_RUN', false);

/* ===== Вызов ndmc ===== */
function run_cmd($cmd, $is_write=false){
    if ($is_write && DRY_RUN) return ["[DRY-RUN] $cmd", 0];
    $out=[]; $rc=0; exec($cmd.' 2>&1', $out, $rc);
    return [implode("\n", $out), $rc];
}
function ndmc($line, $is_write=false){
    global $NDMC;
    return run_cmd($NDMC.' -c '.escapeshellarg($line), $is_write);
}

/* ===== Парсер таблицы маршрутов ===== */
function get_routes(){
    list($raw,$rc) = ndmc('show ip route', false);
    if ($rc!==0) return [[], $raw, $rc];
    $routes=[]; $lines=preg_split('/\R/',$raw); $seps=0;
    foreach($lines as $ln){
        $line=rtrim($ln);
        if ($line==='') continue;
        if (strpos($line,'===')!==false){ $seps++; continue; }
        if ($seps<2) continue;
        $cols=preg_split('/\s+/',trim($line));
        if (count($cols)<3) continue;
        if (!preg_match('/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/',$cols[0])) continue;
        $routes[]=[
            'dest'=>$cols[0],
            'gw'=>$cols[1]??'',
            'iface'=>$cols[2]??'',
            'flags'=>$cols[3]??'',
            'metric'=>$cols[4]??'',
            'line'=>$line,
        ];
    }
    return [$routes,$raw,0];
}

/* ===== Защита ===== */
function is_protected_dest($dest){
    if ($dest==='0.0.0.0/0') return true;
    if (strpos($dest,'192.168.')===0) return true;
    return false;
}

/* ===== Интерфейсы из `show interface` =====
   Берём типы Wireguard/Proxy + Vlan1/Vlan4 (если найдены).
   Возвращаем список: [['id'=>'Wireguard0','name'=>'Wireguard0','desc'=>'lRussiaAWG','label'=>'lRussiaAWG — Wireguard0'], ...] */
function get_interfaces(){
    list($raw,$rc) = ndmc('show interface', false);
    if ($rc!==0) return [];

    $ifs=[]; $current=null;
    $lines=preg_split('/\R/',$raw);
    foreach($lines as $ln){
        $line=trim($ln);
        if ($line==='') continue;

        // начало блока интерфейса
        if (strpos($line,'Interface, name = "')===0 || strpos($line,'Interface, name = ')===0){
            $current = ['name'=>'','id'=>'','type'=>'','desc'=>'','ifname'=>''];
            // name = "PPPoE0"
            if (preg_match('/name\s*=\s*"([^"]+)"/',$line,$m)) $current['name']=$m[1];
            continue;
        }
        if (!$current) continue;

        if (preg_match('/^\bid\s*:\s*(.+)$/',$line,$m))            $current['id']=trim($m[1]);
        elseif (preg_match('/^\binterface-name\s*:\s*(.+)$/',$line,$m)) $current['ifname']=trim($m[1]);
        elseif (preg_match('/^\btype\s*:\s*(.+)$/',$line,$m))      $current['type']=trim($m[1]);
        elseif (preg_match('/^\bdescription\s*:\s*(.+)$/',$line,$m)) $current['desc']=trim($m[1]);
        // окончание блока — эвристика: новый "Interface," или конец файла
        if (strpos($line,'Interface, name = ')===0){
            // уже начался следующий блок — сбросим предыдущий (но его уже обработали выше)
        }
        // признак конца блока — иногда строка "summary:"; обработаем при встрече следующего Interface
        // здесь ничего
        // Добавим на переходах: когда встречаем строку "link:" (обычно внутри блока есть), не завершаем
        // Дадим явное добавление позже: в конце цикла добавим последний
    }
    // Повторно пропарсим «кусками» по разделителю пустых строк между интерфейсами:
    $ifs=[]; $chunk=[];
    foreach ($lines as $ln){
        if (trim($ln)===''){ if ($chunk){ $ifs[]=$chunk; $chunk=[]; } continue; }
        $chunk[]=$ln;
    }
    if ($chunk) $ifs[]=$chunk;

    $res=[];
    foreach($ifs as $arr){
        $blk=implode("\n",$arr);
        // name/id/type/description/interface-name
        $name=''; $id=''; $type=''; $desc=''; $ifname='';
        if (preg_match('/Interface,\s*name\s*=\s*"([^"]+)"/',$blk,$m)) $name=$m[1];
        if (preg_match('/\nid\s*:\s*([^\r\n]+)/',$blk,$m)) $id=trim($m[1]);
        if (preg_match('/\ninterface-name\s*:\s*([^\r\n]+)/',$blk,$m)) $ifname=trim($m[1]);
        if (preg_match('/\ntype\s*:\s*([^\r\n]+)/',$blk,$m)) $type=trim($m[1]);
        if (preg_match('/\ndescription\s*:\s*([^\r\n]+)/',$blk,$m)) $desc=trim($m[1]);

        // нормализуем ID: предпочитаем id или name, затем interface-name
        $id_final = $id ?: ($name ?: $ifname);
        if ($id_final==='') continue;

        $want=false;
        $idlow = strtolower($id_final);
        $typelow = strtolower($type);

        if (strpos($idlow,'wireguard')===0 || strpos($typelow,'wireguard')!==false) $want=true;
        if (strpos($idlow,'opkgtun')===0 || strpos($typelow,'opkgtun')!==false) $want=true;
        if (strpos($idlow,'openvpn')===0 || strpos($typelow,'openvpn')!==false) $want=true;
        if (strpos($idlow,'proxy')===0     || strpos($typelow,'proxy')!==false)     $want=true;
        if (stripos($id_final,'Vlan1')!==false) $want=true;
        if (stripos($id_final,'Vlan4')!==false) $want=true;


        if (!$want) continue;

        $label = ($desc? $desc.' — ' : '').$id_final;
        $res[] = ['id'=>$id_final, 'name'=>$name?:$id_final, 'desc'=>$desc, 'type'=>$type, 'label'=>$label];
    }

    // Уникальные по id
    $uniq=[]; $out=[];
    foreach($res as $r){ if(isset($uniq[$r['id']])) continue; $uniq[$r['id']]=1; $out[]=$r; }
    return $out;
}

/* ===== Маски → CIDR ===== */
function mask_to_prefix($mask){
    $ip = ip2long($mask); if ($ip===false) return null;
    return substr_count(decbin($ip),'1');
}
function ip_mask_to_cidr($ip, $mask){
    $m=ip2long($mask); $i=ip2long($ip);
    if ($m===false||$i===false) return null;
    $pref=mask_to_prefix($mask); if ($pref===null) return null;
    $net=long2ip($i & $m);
    return $net.'/'.$pref;
}
function parse_net_list($text){
    $out=[]; $text=str_replace([",",";"],"\n",$text);
    foreach(preg_split('/\R+/',$text) as $line){
        $line=trim($line); if($line==='') continue;
        if (preg_match('/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/',$line)){ $out[]=$line; continue; }
        if (preg_match('/^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})$/',$line,$m)){
            $cidr=ip_mask_to_cidr($m[1],$m[2]); if($cidr) $out[]=$cidr;
        }
    }
    return array_values(array_unique($out));
}

/* ===== Действия ===== */
$modal = ''; $errs=[];
if ($_SERVER['REQUEST_METHOD']==='POST'){
    $act = $_POST['act'] ?? '';
    if ($act==='move'){
        $iface = trim($_POST['iface'] ?? '');
        $sel   = $_POST['sel'] ?? [];
        if ($iface==='') $errs[]='Не выбран интерфейс.';
        if (!$sel)       $errs[]='Не выбраны маршруты.';
        if (!$errs){
            $buf="";
            foreach ($sel as $cidr){
                $cidr=trim($cidr);
                if (is_protected_dest($cidr)){ $buf.="SKIP protected: $cidr\n"; continue; }
                list($o1,$c1)=ndmc('no ip route '.$cidr,true);
                list($o2,$c2)=ndmc('ip route '.$cidr.' '.$iface.' auto reject',true);
                $buf.="MOVE $cidr -> $iface\n$o1\n$o2\n\n";
            }
            $modal = htmlspecialchars($buf);
        }
    } elseif ($act==='del'){
        $sel = $_POST['sel'] ?? [];
        if (!$sel) $errs[]='Не выбраны маршруты.';
        if (!$errs){
            $buf="";
            foreach ($sel as $cidr){
                if (is_protected_dest($cidr)){ $buf.="SKIP protected: $cidr\n"; continue; }
                list($o,$c)=ndmc('no ip route '.$cidr,true);
                $buf.="DEL $cidr\n$o\n\n";
            }
            $modal = htmlspecialchars($buf);
        }
    } elseif ($act==='bulk_add'){
        $iface = trim($_POST['iface'] ?? '');
        $nets  = parse_net_list($_POST['nets'] ?? '');
        if ($iface==='') $errs[]='Не выбран интерфейс.';
        if (!$nets)      $errs[]='Не найдено ни одной сети.';
        if (!$errs){
            $buf="";
            foreach ($nets as $cidr){
                if (is_protected_dest($cidr)){ $buf.="SKIP protected: $cidr\n"; continue; }
                list($o,$c)=ndmc('ip route '.$cidr.' '.$iface.' auto reject',true);
                $buf.="ADD $cidr via $iface\n$o\n\n";
            }
            $modal = htmlspecialchars($buf);
        }
    }
}

/* ===== Данные для UI ===== */
list($routes,$raw,$rc)=get_routes();
$iface_opts = get_interfaces();
$iface_labels = [];
foreach($iface_opts as $x){ $iface_labels[$x['id']]=$x['label']; }
?>
<!DOCTYPE html><html lang="ru"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>Статические маршруты</title>
<style>
:root{--bg:#0b0b10;--fg:#f5f7fb;--muted:#a7adbb;--card:#151823;--line:#222738;--acc:#5aa7ff;--danger:#ff6b6b;--ok:#7bd88f}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--fg);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif}
h1,h2,h3{margin:16px 16px 8px} .container{padding:0 12px 90px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;margin:12px}
.small{color:var(--muted);font-size:13px} code{background:#111522;border:1px solid var(--line);padding:1px 4px;border-radius:6px}

.table-wrap{overflow:auto;margin:12px;border-radius:10px;border:1px solid var(--line)}
table{border-collapse:separate;border-spacing:0;width:100%;min-width:520px;background:#0f1320}
th,td{padding:10px 12px;border-bottom:1px solid var(--line);font-size:14px;white-space:nowrap}
th{position:sticky;top:0;background:#101528;color:#cfe1ff;text-align:left;z-index:1}
tr:hover{background:#11172a} td.c{width:44px} input[type=checkbox]{width:20px;height:20px}
.badge{display:inline-block;padding:2px 6px;border-radius:6px;border:1px solid var(--line);background:#121824;color:#cbd5e1}
.protect{opacity:.6}

.toolbar{position:sticky;bottom:0;left:0;right:0;background:linear-gradient(180deg,rgba(11,11,16,0),rgba(11,11,16,.85) 40%,rgba(11,11,16,.95));padding:10px;border-top:1px solid var(--line);display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.btn{appearance:none;border:1px solid var(--line);background:#151b2a;color:var(--fg);padding:10px 12px;border-radius:10px;font-size:15px;cursor:pointer}
.btn:hover{border-color:#334} .btn.acc{border-color:#2a66ff;background:#173061} .btn.danger{border-color:#7a1d1d;background:#2a1212}
select,textarea{background:#0f1422;color:var(--fg);border:1px solid var(--line);border-radius:10px;padding:8px}
textarea{width:100%;min-height:120px} .count{margin-left:auto;color:#cfe1ff}
@media (max-width:640px){th,td{padding:8px}.btn{padding:9px 10px}}

.modal{position:fixed;inset:0;background:rgba(0,0,0,.6);display:none;align-items:center;justify-content:center;padding:16px}
.modal .box{max-width:900px;width:100%;background:#0f1320;border:1px solid var(--line);border-radius:12px;overflow:hidden}
.modal header{display:flex;align-items:center;justify-content:space-between;padding:10px 12px;border-bottom:1px solid var(--line);background:#101528}
.modal pre{margin:0;max-height:70vh;overflow:auto;padding:12px;white-space:pre-wrap}
</style>
</head><body>
<div class="container">

<h2>Статические маршруты</h2>
<div class="card">
  <b>Защита:</b> нельзя выбирать/удалять/переносить <code>0.0.0.0/0</code> и любые <code>192.168.x.x</code>.
  <span class="small">Команды через <code><?=htmlspecialchars($NDMC)?></code>.</span>
</div>

<?php foreach($errs as $e): ?><div class="card" style="border-color:#7a1d1d;background:#2a1212"><?=htmlspecialchars($e)?></div><?php endforeach; ?>

<!-- ===== Массовое добавление (СВЕРХУ) ===== -->
<h3>Массовое добавление</h3>
<form method="post" class="card">
  <div class="small" style="margin-bottom:6px">
    Поддерживаются форматы: <code>138.128.136.0/21</code> или <code>10.99.0.0 255.255.252.0</code> (по одной сети в строке или через запятую/точку с запятой).
  </div>
  <textarea name="nets" placeholder="138.128.136.0/21
10.99.0.0 255.255.252.0"></textarea>
  <div style="display:flex;gap:8px;align-items:center;margin-top:8px;flex-wrap:wrap">
    <label>Интерфейс:
      <select name="iface" required>
        <option value="">— выбрать —</option>
        <?php foreach($iface_opts as $if): ?>
          <option value="<?=htmlspecialchars($if['id'])?>"><?=htmlspecialchars($if['label'])?></option>
        <?php endforeach; ?>
      </select>
    </label>
    <button type="submit" name="act" value="bulk_add" class="btn acc">Добавить</button>
    <button type="button" class="btn" id="openModalBtn">Результаты</button>
  </div>
</form>

<!-- ===== Таблица ===== -->
<h3>Текущая таблица</h3>
<form method="post" id="frmRoutes">
<div class="table-wrap">
<table id="rttable">
  <thead>
    <tr>
      <th class="c"><input type="checkbox" id="chkall"></th>
      <th>Destination</th><th>Gateway</th><th>Interface</th><th>F</th><th>Metric</th>
    </tr>
  </thead>
  <tbody>
<?php foreach ($routes as $r): $ban=is_protected_dest($r['dest']); ?>
    <tr data-protected="<?= $ban?1:0 ?>" class="<?= $ban?'protect':'' ?>">
      <td class="c">
        <?php if(!$ban): ?>
          <input type="checkbox" name="sel[]" value="<?=htmlspecialchars($r['dest'])?>">
        <?php else: ?>
          <span class="badge">lock</span>
        <?php endif; ?>
      </td>
      <td><?=htmlspecialchars($r['dest'])?></td>
      <td><?=htmlspecialchars($r['gw'])?></td>
      <td><?=htmlspecialchars(isset($iface_labels[$r['iface']])?$iface_labels[$r['iface']]:$r['iface'])?></td>
      <td><?=htmlspecialchars($r['flags'])?></td>
      <td><?=htmlspecialchars($r['metric'])?></td>
    </tr>
<?php endforeach; ?>
  </tbody>
</table>
</div>

<div class="toolbar">
  <button type="button" class="btn" id="btnSelAll">Выбрать всё</button>
  <button type="button" class="btn" id="btnSelNone">Снять всё</button>
  <button hidden type="button" class="btn" id="btnSelInvert">Инвертировать</button>

  <span style="width:12px;"></span>

  <label class="small">Интерфейс:
    <select name="iface" id="iface">
      <option value="">— выбрать —</option>
      <?php foreach($iface_opts as $if): ?>
        <option value="<?=htmlspecialchars($if['id'])?>"><?=htmlspecialchars($if['label'])?></option>
      <?php endforeach; ?>
    </select>
  </label>

  <button type="submit" name="act" value="move" class="btn acc">Перенести выбранные</button>
  <button type="submit" name="act" value="del"  class="btn danger" onclick="return confirm('Удалить выбранные маршруты?')">Удалить выбранные</button>

  <div class="count" id="selCount">0 выбрано</div>
  <button type="button" class="btn" id="openModalBtn2">Результаты</button>
</div>
</form>

<?php if(!$routes): ?>
  <div class="card" style="border-color:#7a1d1d;background:#2a1212">Не удалось разобрать таблицу маршрутов (код ndmc: <?=$rc?>).</div>
  <div class="card"><pre><?=htmlspecialchars($raw)?></pre></div>
<?php endif; ?>

</div>

<!-- ===== Модал с результатами ===== -->
<div class="modal" id="modal">
  <div class="box">
    <header><div><b>Результаты выполнения</b></div>
      <button class="btn" id="closeModal">Закрыть</button></header>
    <pre id="modalBody"><?= $modal ? $modal : 'Пока пусто.' ?></pre>
  </div>
</div>

<script>
// чекбоксы
const chkAll=document.getElementById('chkall');
const selCount=document.getElementById('selCount');
function eachRow(cb){document.querySelectorAll('#rttable tbody tr').forEach(cb);}
function updateCount(){let n=document.querySelectorAll('#rttable tbody input[type=checkbox]:checked').length; selCount.textContent=n+' выбрано';}
document.getElementById('btnSelAll').onclick=()=>{eachRow(tr=>{if(tr.dataset.protected==='1')return;let cb=tr.querySelector('input[type=checkbox]');if(cb)cb.checked=true;});chkAll.checked=true;updateCount();};
document.getElementById('btnSelNone').onclick=()=>{document.querySelectorAll('#rttable tbody input[type=checkbox]').forEach(cb=>cb.checked=false);chkAll.checked=false;updateCount();};
document.getElementById('btnSelInvert').onclick=()=>{eachRow(tr=>{if(tr.dataset.protected==='1')return;let cb=tr.querySelector('input[type=checkbox]');if(cb)cb.checked=!cb.checked;});updateCount();};
chkAll.onchange=()=>{if(chkAll.checked)document.getElementById('btnSelAll').click();else document.getElementById('btnSelNone').click();};
document.querySelectorAll('#rttable tbody input[type=checkbox]').forEach(cb=>cb.addEventListener('change',updateCount)); updateCount();

// модал
const modal=document.getElementById('modal'); const closeModal=document.getElementById('closeModal');
function openModal(){modal.style.display='flex';}
function close(){modal.style.display='none';}
closeModal.onclick=close;
document.getElementById('openModalBtn').onclick=openModal;
document.getElementById('openModalBtn2').onclick=openModal;
// если сервер прислал результаты — открыть автоматически
<?php if ($modal): ?>openModal();<?php endif; ?>
</script>

</body></html>
