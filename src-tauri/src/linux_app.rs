use crate::logic;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet, env, fs, path::PathBuf, process::Command, sync::Mutex,
    thread, time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use sysinfo::{Process, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use tauri::{menu::{Menu, MenuItem}, tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent}, AppHandle, Manager};

const TASK: &str = "maatram-hardlock";
const DOG: &str = "maatram-hardlock-watchdog";
const MAX_MIN: u32 = 90;
const MAX_CUSTOM: usize = 30;
const API: &str = "https://maatram.co.in/api/link";
const BEGIN: &str = "# MAATRAM-BEGIN";
const END: &str = "# MAATRAM-END";
static IO: Mutex<()> = Mutex::new(());

#[derive(Serialize, Deserialize, Clone)]
struct Lock { start_ms:u64, end_ms:u64, sites:Vec<String>, apps:Vec<String>, blocked:u32, #[serde(default)] seen_ms:u64 }
#[derive(Serialize)]
struct State { active:bool, remaining_secs:u64, total_secs:u64, blocked:u32, custom_sites:Vec<String>, custom_apps:Vec<String> }
#[derive(Serialize)]
struct Blocklist { sites:Vec<&'static str>, apps:Vec<&'static str> }

const LINUX_APPS: &[&str] = &[
    "whatsapp-for-linux", "discord", "steam", "steamwebhelper", "telegram-desktop",
    "telegram-desktop-bin", "org.telegram.desktop", "vesktop", "signal-desktop",
    "spotify", "epic-games", "minecraft-launcher", "prismlauncher", "roblox",
];

fn now_ms()->u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d|d.as_millis() as u64).unwrap_or(0) }
fn data_dir()->PathBuf {
    let base=env::var_os("XDG_DATA_HOME").map(PathBuf::from).or_else(||env::var_os("HOME").map(|h|PathBuf::from(h).join(".local/share"))).unwrap_or_else(||PathBuf::from("/tmp"));
    let d=base.join("maatram-hardlock"); let _=fs::create_dir_all(&d); d
}
fn lock_path()->PathBuf { data_dir().join("lock.json") }
fn hosts_path()->PathBuf { PathBuf::from("/etc/hosts") }
fn guard()->std::sync::MutexGuard<'static,()> { IO.lock().unwrap_or_else(|e|e.into_inner()) }
fn load_raw()->Option<Lock>{serde_json::from_str(&fs::read_to_string(lock_path()).ok()?).ok()}
fn load()->Option<Lock>{let _g=guard();load_raw()}
fn write_raw(l:&Lock)->Result<(),String>{let json=serde_json::to_string(l).map_err(|e|e.to_string())?;let tmp=data_dir().join("lock.json.tmp");fs::write(&tmp,json).and_then(|_|fs::rename(tmp,lock_path())).map_err(|e|format!("Cannot save lock: {e}"))}
fn save(l:&Lock)->Result<(),String>{let _g=guard();write_raw(l)}
fn bump(n:u32){let _g=guard();if let Some(mut l)=load_raw(){l.blocked+=n;let _=write_raw(&l);}}
fn advance(last:&mut Option<Instant>)->Option<Lock>{let _g=guard();let mut l=load_raw()?;let now=now_ms();let expected=last.map_or(0,|t|t.elapsed().as_millis() as u64);let end=logic::shift_end(l.end_ms,l.seen_ms,now,expected);l.start_ms=(i128::from(l.start_ms)+i128::from(end)-i128::from(l.end_ms)).max(0) as u64;l.end_ms=end;l.seen_ms=now;*last=Some(Instant::now());let _=write_raw(&l);Some(l)}
fn link_path()->PathBuf{data_dir().join("link.txt")}
fn autostart_path()->PathBuf{
    let base=env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).or_else(||env::var_os("HOME").map(|h|PathBuf::from(h).join(".config"))).unwrap_or_else(||PathBuf::from("/tmp"));
    base.join("autostart").join("maatram-hardlock.desktop")
}
fn enable_autostart(){
    let Ok(exe)=env::current_exe() else{return};
    let path=autostart_path();
    let Some(parent)=path.parent() else{return};
    if fs::create_dir_all(parent).is_err(){return}
    let exe=exe.to_string_lossy().replace('\\',"\\\\").replace('"',"\\\"").replace('%',"%%");
    let desktop=format!("[Desktop Entry]\nType=Application\nName=Maatram Hard Lock\nComment=Keep an active Hard Lock running\nExec=\"{exe}\" --autostart\nTerminal=false\nX-GNOME-Autostart-enabled=true\n");
    let _=fs::write(path,desktop);
}
fn disable_autostart(){let _=fs::remove_file(autostart_path());}
fn link_code()->String{fs::read_to_string(link_path()).unwrap_or_default().trim().to_string()}
fn is_locked()->bool{load().is_some_and(|l|now_ms()<l.end_ms)}
fn run_cmd(cmd:&str,args:&[&str])->bool{Command::new(cmd).args(args).output().map(|o|o.status.success()).unwrap_or(false)}
fn curl(args:&[&str])->Option<String>{let o=Command::new("curl").args(["-s","-f","-m","8"]).args(args).output().ok()?;o.status.success().then(||String::from_utf8_lossy(&o.stdout).into_owned())}
fn exe_name()->String{env::current_exe().ok().and_then(|p|p.file_name().map(|n|n.to_string_lossy().to_lowercase())).unwrap_or_default()}
fn is_dog(p:&Process)->bool{p.cmd().iter().any(|a|a=="--watchdog")}
fn refresh(sys:&mut System){sys.refresh_processes_specifics(ProcessesToUpdate::All,true,ProcessRefreshKind::nothing().with_cmd(UpdateKind::OnlyIfNotSet));}
fn peers(sys:&mut System)->(usize,usize){refresh(sys);let(me,name)=(std::process::id(),exe_name());let(mut mains,mut dogs)=(0,0);for(pid,p)in sys.processes(){if pid.as_u32()==me||p.name().to_string_lossy().to_lowercase()!=name{continue}if is_dog(p){if pid.as_u32()<me{dogs+=1}}else{mains+=1}}(mains,dogs)}
fn spawn_self(arg:&str){if let Ok(exe)=env::current_exe(){let _=Command::new(exe).arg(arg).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn();}}
fn launch(_task:&str,arg:&str){spawn_self(arg)}
fn merged_apps(l:&Lock)->HashSet<String>{LINUX_APPS.iter().map(|s|s.to_string()).chain(l.apps.iter().cloned()).collect()}
fn read_hosts()->String{fs::read_to_string(hosts_path()).unwrap_or_default()}
fn write_hosts_privileged(content:&str)->Result<(),String>{
    let tmp=data_dir().join("hosts.new");
    fs::write(&tmp,content).map_err(|e|format!("Cannot prepare hosts file: {e}"))?;
    let path=tmp.to_string_lossy().to_string();
    // pkexec prompts through the desktop's polkit agent; the application itself never runs as root.
    let ok=run_cmd("pkexec",&["/usr/bin/install","-o","root","-g","root","-m","0644",&path,"/etc/hosts"]);
    let _=fs::remove_file(&tmp);
    if ok { Ok(()) } else { Err("Permission to update /etc/hosts was denied or pkexec is unavailable. Install polkit and approve the permission prompt.".into()) }
}
fn hosts_block(custom:&[String])->String{
    let mut sites=std::collections::BTreeSet::new();
    for s in logic::SITES.iter().copied().chain(custom.iter().map(String::as_str)){sites.insert(s.to_string());sites.insert(format!("www.{s}"));}
    for h in logic::EXTRA_HOSTS{sites.insert((*h).to_string());}
    let mut out=format!("{BEGIN}\n");
    for h in sites{out.push_str(&format!("0.0.0.0 {h}\n::1 {h}\n"));}
    out.push_str(&format!("{END}\n"));out
}
fn strip_hosts(hosts:&str)->String{
    let lines:Vec<&str>=hosts.lines().collect();
    let mut out=Vec::new();
    let mut i=0;
    while i<lines.len(){
        if lines[i].trim()==BEGIN {
            if let Some(off)=lines[i+1..].iter().position(|line|line.trim()==END) {
                i += off + 2;
            } else {
                // A damaged block must not cause unrelated host entries to be deleted.
                i += 1;
            }
            continue;
        }
        out.push(lines[i]);
        i += 1;
    }
    let mut result=out.join("\n");
    if !result.is_empty(){result.push('\n');}
    result
}
fn has_hosts_block(hosts:&str)->bool{hosts.lines().any(|l|l.trim()==BEGIN)}
fn apply_hosts(l:&Lock)->Result<(),String>{let cur=read_hosts();let want=format!("{}{}",strip_hosts(&cur),hosts_block(&l.sites));if want!=cur{write_hosts_privileged(&want)?;}Ok(())}
fn restore_hosts(){let cur=read_hosts();if has_hosts_block(&cur){let _=write_hosts_privileged(&strip_hosts(&cur));}}
fn end_lock(){restore_hosts();let _g=guard();let _=fs::remove_file(lock_path());drop(_g);if link_code().is_empty(){disable_autostart();}}
fn show_flag()->PathBuf{data_dir().join("show")}
fn tick(sys:&mut System,last_dog_launch:&mut Instant,seen:&mut HashSet<String>,checked:&mut Option<Instant>){
    let Some(l)=advance(checked)else{return};if now_ms()>=l.end_ms{end_lock();return}
    let _=apply_hosts(&l);refresh(sys);let(names,me,exe)=(merged_apps(&l),std::process::id(),exe_name());let mut dogs=0;let mut killed=HashSet::new();
    for(pid,p)in sys.processes(){let n=p.name().to_string_lossy().to_lowercase();if pid.as_u32()!=me && names.contains(&n){if p.kill(){killed.insert(n);}}else if n==exe&&pid.as_u32()!=me&&is_dog(p){dogs+=1}}
    let new=killed.difference(seen).count() as u32;if new>0{bump(new)}*seen=killed;
    if dogs==0&&last_dog_launch.elapsed()>Duration::from_secs(5){launch(DOG,"--watchdog");*last_dog_launch=Instant::now();}
}
fn enforce(app:AppHandle){let mut sys=System::new();let mut last=Instant::now()-Duration::from_secs(60);let mut seen=HashSet::new();let mut checked=None;let mut last_poll=Instant::now()-Duration::from_secs(60);loop{tick(&mut sys,&mut last,&mut seen,&mut checked);if last_poll.elapsed()>=Duration::from_secs(60){last_poll=Instant::now();thread::spawn(poll_link);}if fs::remove_file(show_flag()).is_ok(){show(&app)}thread::sleep(Duration::from_secs(1));}}
fn watchdog(){let mut sys=System::new();let mut last=Instant::now()-Duration::from_secs(60);let mut checked=None;loop{let(mains,older)=peers(&mut sys);if older>0{return}let lock=if mains==0{advance(&mut checked)}else{checked=None;load()};match lock{None=>return,Some(l)if now_ms()>=l.end_ms=>{end_lock();return},Some(_)=>if mains==0&&last.elapsed()>Duration::from_secs(5){launch(TASK,"--autostart");last=Instant::now();}}thread::sleep(Duration::from_secs(2));}}
fn poll_link(){let code=link_code();if code.is_empty(){return}let Some(body)=curl(&[&format!("{API}?code={code}")])else{return};let Ok(d)=serde_json::from_str::<serde_json::Value>(&body)else{return};let n=|k:&str|d[k].as_u64().unwrap_or(0);let now=now_ms();let ours=load().filter(|l|now<l.end_ms).map_or(0,|l|l.end_ms);if let Some(end)=logic::link_end(n("end"),n("now"),n("minutes"),now,ours,u64::from(MAX_MIN)){adopt(end)}}
fn adopt(end:u64){let now=now_ms();let l={let _g=guard();let l=match load_raw(){Some(l)if now<l.end_ms=>Lock{end_ms:l.end_ms.max(end),..l},_=>Lock{start_ms:now,end_ms:end,sites:vec![],apps:vec![],blocked:0,seen_ms:now}};if write_raw(&l).is_err(){return}l};let _=apply_hosts(&l);arm();}
fn push_link(minutes:u32){let code=link_code();if code.is_empty(){return}let body=serde_json::json!({"code":code,"minutes":minutes,"by":"pc"}).to_string();let _=curl(&["-X","POST","-H","Content-Type: application/json","-d",&body,API]);}
fn cleanup(){ {let _g=guard();let _=fs::remove_file(lock_path());let _=fs::remove_file(link_path());}thread::sleep(Duration::from_secs(3));let mut sys=System::new();refresh(&mut sys);let(me,name)=(std::process::id(),exe_name());for(pid,p)in sys.processes(){if pid.as_u32()!=me&&p.name().to_string_lossy().to_lowercase()==name{p.kill();}}end_lock();}
#[tauri::command] fn get_blocklist()->Blocklist{let mut sites:Vec<&'static str>=logic::SITES.to_vec();sites.extend_from_slice(logic::EXTRA_HOSTS);Blocklist{sites,apps:LINUX_APPS.to_vec()}}
#[tauri::command] fn get_state()->State{match load(){Some(l)if now_ms()<l.end_ms=>State{active:true,remaining_secs:logic::remaining_secs(l.end_ms,now_ms()),total_secs:(l.end_ms-l.start_ms)/1000,blocked:l.blocked,custom_sites:l.sites,custom_apps:l.apps},_=>State{active:false,remaining_secs:0,total_secs:0,blocked:0,custom_sites:vec![],custom_apps:vec![]}}}
fn clean_linux_app(raw:&str)->Result<String,String>{let n=raw.trim().rsplit('/').next().unwrap_or("").trim().to_lowercase();let ok=(2..=100).contains(&n.len())&&n.chars().all(|c|c.is_ascii_lowercase()||c.is_ascii_digit()||matches!(c,'.'|'_'|'-'));if !ok{return Err(format!("Not a valid Linux process name: {}",raw.trim()))}if ["systemd","init","gnome-shell","plasmashell","xorg","xwayland","weston","sway","kwin_wayland","wayland","dbus-daemon","dbus-broker","polkitd","bash","sh","zsh","fish","maatram-hardlock"].contains(&n.as_str()){return Err(format!("{n} is protected and cannot be blocked"))}Ok(n)}
#[tauri::command] async fn start_lock(minutes:u32,sites:Vec<String>,apps:Vec<String>)->Result<(),String>{
    if !(1..=MAX_MIN).contains(&minutes){return Err(format!("Pick 1 to {MAX_MIN} minutes"))}if sites.len()+apps.len()>MAX_CUSTOM{return Err(format!("Add at most {MAX_CUSTOM} custom entries"))}if is_locked(){return Err("A lock is already running".into())}
    let sites=sites.iter().map(|s|logic::clean_site(s)).collect::<Result<Vec<_>,_>>()?;let apps=apps.iter().map(|s|clean_linux_app(s)).collect::<Result<Vec<_>,_>>()?;let now=now_ms();let l=Lock{start_ms:now,end_ms:now+u64::from(minutes)*60_000,sites,apps,blocked:0,seen_ms:now};save(&l)?;
    if let Err(e)=apply_hosts(&l){let _g=guard();let _=fs::remove_file(lock_path());return Err(e)}arm();thread::spawn(move||push_link(minutes));Ok(())
}
fn arm(){enable_autostart();launch(TASK,"--autostart");launch(DOG,"--watchdog");}
#[tauri::command] fn get_link()->String{link_code()}
#[tauri::command] async fn set_link(code:String)->Result<String,String>{let c=logic::clean_code(&code)?;if c.is_empty(){let _=fs::remove_file(link_path());if !is_locked(){disable_autostart();}}else{fs::write(link_path(),&c).map_err(|e|format!("Cannot save the link code: {e}"))?;enable_autostart();thread::spawn(poll_link);}Ok(c)}
fn show(app:&AppHandle){if let Some(w)=app.get_webview_window("main"){let _=w.show();let _=w.unminimize();let _=w.set_focus();}}
pub fn run(){
    if env::args().any(|a|a=="--watchdog"){return watchdog()}if env::args().any(|a|a=="--cleanup"){return cleanup()}
    if peers(&mut System::new()).0>0{let _=fs::write(show_flag(),"");return}let _=fs::remove_file(show_flag());
    tauri::Builder::default().setup(|app|{
        let open=MenuItem::with_id(app,"open","Open",true,None::<&str>)?;let quit=MenuItem::with_id(app,"quit","Quit",true,None::<&str>)?;let menu=Menu::with_items(app,&[&open,&quit])?;
        let mut tray=TrayIconBuilder::new().menu(&menu).show_menu_on_left_click(false).on_menu_event(|app,ev|match ev.id().as_ref(){"open"=>show(app),"quit" if is_locked() =>show(app),"quit"=>app.exit(0),_=>{}}).tooltip("Maatram Hard Lock").on_tray_icon_event(|tray,ev|{if let TrayIconEvent::Click{button:MouseButton::Left,button_state:MouseButtonState::Up,..}=ev{show(tray.app_handle());}});
        if let Some(icon)=app.default_window_icon(){tray=tray.icon(icon.clone());}tray.build(app)?;
        if !(env::args().any(|a|a=="--autostart")&&(is_locked()||!link_code().is_empty())){show(app.handle());}
        let handle=app.handle().clone();thread::spawn(move||enforce(handle));Ok(())
    }).on_window_event(|window,event|{if let tauri::WindowEvent::CloseRequested{api,..}=event{if is_locked()||!link_code().is_empty(){api.prevent_close();let _=window.hide();}}})
    .invoke_handler(tauri::generate_handler![get_state,get_blocklist,start_lock,get_link,set_link]).run(tauri::generate_context!()).expect("failed to start Maatram Hard Lock");
}
