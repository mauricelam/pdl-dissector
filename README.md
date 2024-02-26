## Architecture

### Parsing phases
1. Phase 1 is using the PDL parser to parse the file into a `pdl_compiler::ast::File` object
2. Phase 2 analyzes the AST and adds field size annotations using `pdl_compiler::analyzer::analyze`
3. Phase 3 creates a `pdl_compiler::analyzer::Scope`, which adds child / parent relationships.

Code in this project starts at phase 4

4. Phase 4 uses the analyzed information to extract relevant information out to `DissectorInfo` structs.
5. Phase 5 takes those `DissectorInfo` instances and generate the lua code from it.

## TODO
- [ ] Set up integration test with tshark
- [ ] A way to specify how to add to DissectorTable