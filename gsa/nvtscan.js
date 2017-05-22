console.log("Run a NVT (by OID) against host like this:");
console.log("scanHostWithNVT('localhost', '1.3.6.1.4.1.25623.1.0.106223');\\n");

function scanHostWithNVT(host, oid) {

  const nvt_oid = oid;
  const target = host;

  // Base config: Empty and static configuration template.
  const base = '085569ce-73ed-11df-83c3-002264764cea';

  // Scanner config: OpenVAS Default
  const scanner_id = '08b69003-5fc2-4037-a479-93b440211c73';

  let scan_config;

  console.log('Creating new Scan Configuration with NVT ...');

  gmp.scanconfig.create({
    base: base,
    name: nvt_oid,
    comment: '',
    scanner_id: scanner_id
  })
  .then(response => response.data, err => {
    console.log('Scan Configuration already exist. Reusing it...');

    return gmp.scanconfigs.get({
      filter: 'name=' + nvt_oid
    }).then(response => response.getEntries()[0]);
  })
  .then(config => {
    console.log("Scan Configuration created/re-using: ", config.id);

    scan_config = config;

    let nvts = {
      '1.3.6.1.4.1.25623.1.0.14259': '1',
      '1.3.6.1.4.1.25623.1.0.100315': '1'
    };

    return gmp.scanconfig.saveScanConfigFamily({
      config_name: nvt_oid,
      family_name: 'Port Scanners',
      id: config.id,
      selected: nvts
    });
  })
  .then(() => {
    return gmp.nvt.get({
      id: nvt_oid
    });
  })
  .then(response => {
    let nvt = response.data;
    let family = nvt.family;
    return family;
  })
  .then(family => {
    let nvts = {
      [nvt_oid]: '1'
    };
    return gmp.scanconfig.saveScanConfigFamily({
      config_name: nvt_oid,
      family_name: family,
      id: scan_config.id,
      selected: nvts
    });
  }).then(() => {
    console.log('Scan Configugration configured: ' + scan_config.id +
      ' (Name: ' + scan_config.name + ')' );
    console.log('Creating new target from host ...');

    return gmp.target.create({
      name: target,
      hosts: target,
      target_source: 'manual',
      port_list_id: 'c7e03b6c-3bbe-11e1-a057-406186ea4fc5',
      port: 22,
      alive_tests: 'Scan Config Default'
    })
    .then(response => {
      console.log('Target created: ' + response.data.id);

      return response.data;
    }, err => {
      console.log('Target already exists. Re-using this target.');

      return gmp.targets.get({
        filter: 'name=' + target
      }).then(response => response.getEntries()[0]);
    });
  }).then(target_obj => {
    console.log('Using Target ' + target_obj.id + ' ...');

    let date = new Date().toISOString();
    let name = target + '_' + nvt_oid + '_' + date;
    return gmp.task.create({
      name: name,
      config_id: scan_config.id,
      target_id: target_obj.id,
      scanner_id: scanner_id,
      scanner_type: '1',
      in_assets: '1',
      apply_overrides: '1',
      min_qod: '',
      auto_delete: 'keep',
      auto_delete_data: '5',
      alterable: '1'
    });
  })
  .then(response => {
    let task_id = response.data.id;
    console.log('Starting task ' + task_id + ' ... please go to respective ' +
      'pages to track progress ...');
    return gmp.task.start({
      id: task_id
    });
  })
  .then(response => {
    console.log('Task ' + response.data.id + ' has been started');
  })
  .catch(err => {
    console.log('An error occured.', err.message);
  });
}