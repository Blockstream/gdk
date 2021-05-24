swift_sources = ['Sources/GreenAddress/GreenAddress.swift']

target_cmd_line = []
foreach target : ['build', 'test']
    target_cmd_line += ['swift', target, '--package-path', join_paths(meson.source_root(), 'src', 'swift', 'GreenAddress'),
                       '-Xswiftc', '-I../..',
                       '-Xswiftc', '-I' + join_paths(meson.source_root(), 'include'),
                       '-Xswiftc', '-I' + join_paths(meson.build_root(), 'libwally-core', 'build', 'include'),
                       '-Xswiftc', '-L' + join_paths(meson.build_root(), 'src')]
endforeach

ga_swift = custom_target('GreenAddress',
              command : target_cmd_line[0],
              input : swift_sources,
              output : ['GreenAddress.swiftmodule'],
              depends : libga,
              build_by_default : true)
