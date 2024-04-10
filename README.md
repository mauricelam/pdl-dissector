## Architecture

### Parsing phases
1. Phase 1 is using the PDL parser to parse the file into a `pdl_compiler::ast::File` object
2. Phase 2 analyzes the AST and adds field size annotations using `pdl_compiler::analyzer::analyze`
3. Phase 3 creates a `pdl_compiler::analyzer::Scope`, which adds child / parent relationships.

Code in this project starts at phase 4

4. Phase 4 uses the analyzed information to extract relevant information out to `DissectorInfo` structs.
5. Phase 5 takes those `DissectorInfo` instances and generate the lua code from it.

## Usage

```sh
# cargo run <PDL file> <"packet" name> > <output>
cargo run tests/test_le.pdl TopLevel > tests/test_le_dissector.lua
```

This will generate a lua dissector file, which has the protocol `TopLevel_protocol` inside. The
protocol can be registered using something like:

```lua
DissectorTable.get("tcp.port"):add(8000, TopLevel_protocol)
```

Alternatively, you can simply add this as one of the "decode as" dissectors:

```lua
DissectorTable.get("tcp.port"):add_for_decode_as(TopLevel_protocol)
```

This can be done by manually adding to the generated file, appending to the file using a bash
script, or using lua's `require`.

## Examples

To see some examples of the generated lua files, see the `examples/` directory. You can also refer
to `tests/integration_test.rs`, which runs the generated dissector and asserts it against the
dissected output.

## TODO
- [ ] Extract comments from the PDL file and put them in the ProtoField.descr field.