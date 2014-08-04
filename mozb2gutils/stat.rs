use std::io::fs;
use std::os;

fn main() {
    let args = os::args();

    let path = match args.as_slice() {
        [_, ref path] => path.as_slice(),
        _ => fail!("Invalid command line arguments.")
    };

    let p = Path::new(path);

    match fs::stat(&p) {
        Ok(stat) => {
            println!("{:u}", stat.modified);
        }
        Err(_) => {fail!("Path not found")}
    }
}
