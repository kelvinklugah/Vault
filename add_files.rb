require 'xcodeproj'

proj_path = ARGV[0] || 'ios/App/App.xcodeproj'
proj = Xcodeproj::Project.open(proj_path)
target = proj.targets.find { |t| t.name == 'App' } or abort('App target not found')
group = proj.main_group['App'] or abort('App group not found')

%w[ViewController.swift VaultBioPlugin.swift].each do |name|
  next if group.files.any? { |f| f.path == name }
  ref = group.new_file(name)
  target.add_file_references([ref])
end

proj.save
puts "added Swift files to #{proj_path}"
