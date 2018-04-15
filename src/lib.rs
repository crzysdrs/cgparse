#[macro_use]
extern crate nom;
use nom::alphanumeric;
use nom::alpha;
use std::str::FromStr;

#[cfg(test)]
mod tests {
    macro_rules! test_file {
        ($name:ident, $file:expr) => {
            #[test]
            fn $name () {
                let input = include_str!($file);
                let res = ::callgrind(input[..].as_bytes());
                assert!(res.is_done());
                let done = res.unwrap();
                if done.0.len() > 0 {
                    println!("{:?}", ::std::str::from_utf8(done.0))
                }
                assert_eq!(done.0.len(), 0);
            }
        }
    }

    test_file!(simple, "simple.callgrind");
    test_file!(extended, "extended.callgrind");
    test_file!(name_compression, "name_compression.callgrind");
    test_file!(subposition_cmp, "subposition_cmp.callgrind");
    test_file!(subposition_cmp2, "subposition_cmp2.callgrind");
    test_file!(long_names, "long_names.callgrind");
}

#[derive(Debug)]
struct CallgrindFile {
    version: u32,
    creator: Option<String>,
    data : Vec<CallgrindEntry>,
}

#[derive(Debug)]
struct CallgrindEntry {
    header: Vec<HeaderLine>,
    body: Vec<BodyLine>,
}

#[derive(Debug)]
enum InheritedExpr {
    Name(String),
    Mul(u32, String),
}

#[derive(Debug)]
enum HeaderLine {
    Cmd(String),
    Pid(u32),
    Thread(u32),
    Part(u32),
    Description(String, String),
    EventSpec(String, Option<Vec<InheritedExpr>>, Option<String>),
    Events(Vec<String>),
    Positions(bool, bool),
}

#[derive(Debug)]
enum SubDirection
{
    Plus,
    Minus
}

#[derive(Debug)]
enum SubPosition {
    Absolute(u32),
    Relative(SubDirection, u32),
    Same,
}

type SubPositionVec = Vec<SubPosition>;

#[derive(Debug)]
enum BodyLine {
    Comment,
    Cost(Vec<SubPosition>, Option<Vec<u32>>),
    PositionSpec(PositionType, Position),
    CallSpec(u32, SubPositionVec, Box<BodyLine>),
    UncondJumpSpec(u32, SubPositionVec),
    CondJumpSpec(u32, u32, SubPositionVec),
}

#[derive(Debug)]
struct Position {
    id: Option<u32>,
    val: Option<String>,
}

#[derive(Debug)]
enum PositionType {
    Object, //"ob"
    File, //"fi"
    //"fl"
    //"fe"
    Function, //"fn"
    CallObject, //"cob"
    CallFile, //"cfi"
    //"cfl"
    CallFunction, //"cfn"
}

fn default_version(version: Option<u32>) -> u32 {
    version.unwrap_or(1)
}

named!(callgrind<&[u8], CallgrindFile>,
       do_parse!(
           opt!(format_spec) >>
           version: map!(opt!(format_version), default_version) >>
           creator: opt!(creator) >>
               data: many0!(part_data) >>
           (CallgrindFile {version, creator:creator.map(|s| s.to_owned()), data })
       )
);

named!(format_spec<&[u8], &[u8]>,
       tag!("# callgrind format\n")
);

named!(format_version<&[u8], u32>,
       do_parse!(
           tag!("version: ") >>
               version: number >>
               tag!("\n") >>
               (version)
       )
);

named!(creator<&[u8], &str>,
       do_parse!(
           tag!("creator:") >>
               creator: no_newline_chars >>
               tag!("\n") >>
               (creator)
       )
);

named!(part_data<&[u8], CallgrindEntry>,
       do_parse!(
           header: many1!(do_parse!(l: header_line >> tag!("\n") >> (l) )) >>
               body: many1!(do_parse!(l: body_line >> tag!("\n") >> (l) )) >>
               many0!(comment_or_empty) >>
           (CallgrindEntry {header, body})
       )
);

named!(header_line<&[u8], HeaderLine>,
       do_parse!(
           comment_or_empty >>
               line: alt!(
                   part_detail
                       | description
                       | event_specification
                       | cost_line_def
               ) >>
               (line)
       )
);

named!(part_detail<&[u8], HeaderLine>,
       alt!(
           target_command
               | target_id
       )
);

named!(target_command<&[u8], HeaderLine>,
       do_parse!(
           tag!("cmd:") >>
           space0 >>
           s: no_newline_chars >>
           (HeaderLine::Cmd(s.to_owned()))
       )
);

named!(no_newline_chars< &[u8], &str>,
       map_res!(map!(complete!(take_until!("\n")), std::str::from_utf8), |s| s)
);

named!(target_id<&[u8], HeaderLine>,
       alt!(do_parse!(tag!("pid") >> n: target_spec >> (HeaderLine::Pid(n)))
            | do_parse!(tag!("thread") >> n: target_spec >> (HeaderLine::Thread(n)))
            | do_parse!(tag!("part") >> n: target_spec >> (HeaderLine::Part(n)))
       )
);

named!(target_spec<&[u8], u32>,
       do_parse!(
           tag!(":") >> space0 >> n: number >> (n)
       )
);

named!(space0<&[u8], &[u8]>,
       take_while!(nom::is_space)
);

named!(space1<&[u8], &[u8]>,
       take_while1!(nom::is_space)
);

named!(description<&[u8], HeaderLine>,
       do_parse!(
           tag!("desc:") >> space0 >> n : name >> space0 >> tag!(":") >> d: no_newline_chars
               >> (HeaderLine::Description(n.to_owned(), d.to_owned()))
       )
);


named!(event_specification<&[u8], HeaderLine>,
       do_parse!(
           tag!("event:") >> space0 >> n: name >> space0 >> inh: opt!(inherited_def) >> long: opt!(long_name_def) >>
               (HeaderLine::EventSpec(n.to_owned(), inh, long))
       )
);

named!(inherited_def<&[u8], Vec<InheritedExpr>>,
       do_parse!(
           tag!("=") >> space0 >> inh: inherited_expr
               >> (inh)
       )
);

named!(inherited_expr<&[u8], Vec<InheritedExpr>>,
       separated_nonempty_list!(
           tuple!(space0, tag!("+"), space0),
           alt!(
               name => {|n: &str| InheritedExpr::Name(n.to_owned())}
               | do_parse!(num : number >> space0 >> opt!(tuple!(tag!("*"), space0)) >> n: name >> (InheritedExpr::Mul(num, n.to_owned())))
           )
       )
);

named!(long_name_def<&[u8], String>,
       do_parse!(
           tag!(":") >> space0 >> n : no_newline_chars >> (n.to_owned())
       )
);

named!(cost_line_def<&[u8], HeaderLine>,
       alt!(
           do_parse!(tag!("events:") >> space0 >> events: separated_nonempty_list!(space1, name) >> (HeaderLine::Events(events.into_iter().map(|s| s.to_owned()).collect())))
          | do_parse!(tag!("positions:") >> space0 >> instr: opt!(tag!("instr")) >> line: opt!(tuple!(space1, tag!("line"))) >> (HeaderLine::Positions(instr.is_some(), line.is_some())))
       )
);

named!(comment_or_empty<&[u8], &[u8]>,
       recognize!(
           many0!(
               alt!(
                   recognize!(tuple!(space0, tag!("\n")))
                   | recognize!(tuple!(tag!("#"), no_newline_chars, tag!("\n")))
               )
           )
       )
);

named!(body_line<&[u8], BodyLine>,
       do_parse!(
           comment_or_empty >>
           line: alt!(
               cost_line
                   | position_spec
                   | call_spec
                   | uncond_jump_spec
                   | cond_jump_spec
           ) >>
               (line)


       )
);

named!(cost_line<&[u8], BodyLine>,
       do_parse!(
           subs: sub_position_list >> costs: opt!(costs) >> (BodyLine::Cost(subs, costs))
       )
);

named!(sub_position_list<&[u8], SubPositionVec>,
       separated_nonempty_list!(space1, sub_position)
);


named!(sub_position<&[u8], SubPosition>,
       alt!(
           number => {|n| SubPosition::Absolute(n)}
           | do_parse!(tag!("+") >> n: number >> (SubPosition::Relative(SubDirection::Plus, n)))
               | do_parse!(tag!("-") >> n: number >> (SubPosition::Relative(SubDirection::Minus, n)))
               | tag!("*") => {|_| SubPosition::Same}
       )
);

named!(costs<&[u8], Vec<u32>>,
       separated_nonempty_list_complete!(space1, number)
);

named!(position_spec<&[u8], BodyLine>,
       do_parse!(
           pos_type: position >>
               tag!("=") >>
               space0 >> pos : position_name >> (BodyLine::PositionSpec(pos_type, pos))
       )
);


named!(position<&[u8], PositionType>,
       alt!(cost_position
            | call_position
       )
);

named!(cost_position<&[u8], PositionType>,
       alt!(tag!("ob") => { |_| PositionType::Object}
            | tag!("fl") => { |_| PositionType::File}
            | tag!("fi") => { |_| PositionType::File}
            | tag!("fe") => { |_| PositionType::File}
            | tag!("fn") => { |_| PositionType::Function}
       )
);

named!(call_position<&[u8], PositionType>,
       alt!(tag!("cob") => { |_| PositionType::CallObject}
            | tag!("cfi") => { |_| PositionType::CallFile }
            | tag!("cfl") => { |_| PositionType::CallFile }
            | tag!("cfn") => { |_| PositionType::CallFunction }
       )
);

named!(position_name<&[u8], Position>,
       do_parse!(
           id: opt!(do_parse!(tag!("(") >> n: number >> tag!(")") >> (n))) >>
           val: opt!(do_parse!(space0 >> n: no_newline_chars >> (n))) >> (Position { id, val: val.map(|s| s.to_owned()) })
       )
);

named!(call_spec<&[u8], BodyLine>,
       do_parse!(
           t : call_line >> tag!("\n") >> costs: cost_line >> (BodyLine::CallSpec(t.0, t.1, Box::new(costs)))
       )
);

named!(call_line<&[u8], (u32, SubPositionVec)>,
       do_parse!(
           tag!("calls=") >> space0 >> n: number >> space1 >> subs: sub_position_list >> (n, subs)
       )
);

named!(uncond_jump_spec<&[u8], BodyLine>,
       do_parse!(
           tag!("jump=") >> space0 >> n: number >> space1 >> subs: sub_position_list >> (BodyLine::UncondJumpSpec(n, subs))
       )
);


named!(cond_jump_spec<&[u8], BodyLine>,
       do_parse!(
           tag!("jcnd=") >> space0 >> n1 : number >> space1 >> n2 : number >> space1 >> subs: sub_position_list >> (BodyLine::CondJumpSpec(n1, n2, subs))
       )
);

named!(number<&[u8], u32>,
       alt!(
           do_parse!(
               tag!("0x") >>
                   num : map_res!(
                       map_res!(recognize!(many1!(nom::hex_digit)), std::str::from_utf8),
                       |s| u32::from_str_radix(s, 16)
                   )
                   >> (num)
           )
           | map_res!(map_res!(recognize!(many1!(nom::digit)), std::str::from_utf8), FromStr::from_str)
       )
);

named!(name<&[u8], &str>,
       map_res!(
           recognize!(
               tuple!(
                   alpha, many0!(alphanumeric)
               )
           ), std::str::from_utf8
       )
);
