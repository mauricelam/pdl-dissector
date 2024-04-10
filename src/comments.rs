use pdl_compiler::{
    analyzer::ast::File,
    ast::{Comment, SourceRange},
};

pub fn find_comments_on_same_line<'a>(file: &'a File, source: &SourceRange) -> Option<&'a Comment> {
    file.comments.iter().find(|comment| {
        comment.loc.file == source.file && comment.loc.start.line == source.end.line
    })
}

pub fn unwrap_comment(s: &str) -> &str {
    s.strip_prefix("/*")
        .and_then(|s| s.strip_suffix("*/"))
        .or_else(|| s.strip_prefix("//"))
        .map(|s| s.trim())
        .unwrap_or_default()
}

pub trait ToLuaExpr {
    fn to_lua_expr(&self) -> String;
}

impl ToLuaExpr for Option<&str> {
    fn to_lua_expr(&self) -> String {
        self.map(|t| format!("\"{t}\"")).unwrap_or("nil".into())
    }
}
