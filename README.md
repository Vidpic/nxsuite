# NXSuite

This package provides functions to edit Nintendo Switch file formats using [hactool](https://github.com/SciresM/hactool) by [SciresM](https://github.com/SciresM) and hackpack by The-4n. Included functions are:

- extract and pack NSP files
- extract, pack and decrypt NCA files
- display informations about NCA file
- retrieve the titlekey from TIK files

## Installation
```
pip install nxsuite
```

## Usage
```
from nxsuite import setup, nsp, nca, tik
```

### Setup
```
setup.prodkeys(p_dir)
setup.sdk_version(sdk_ver)
setup.key_generation(key_gen)
setup.title_id(t_id)
setup.title_version(t_ver)
```

### NSP
```
nsp.exctract(nsp, out_dir, prodkeys=None)
nsp.pack(nca_dir, out_dir, title_id=None, prodkeys=None)
```

### NCA
```
nca.info(nca, prodkeys=None)
nca.decrypt(nca, out_dir, titlekey, prodkeys=None)
nca.extract_romfs(base_nca, update_nca, out_dir, update_titlekey, prodkeys=None)
nca.pack_program(exefs, romfs, logo, out_dir, sdk_version=None, key_generation=None, title_id=None, prodkeys=None)
nca.pack_meta(legal_nca, control_nca, html_doc, program_nca, out_dir, sdk_version=None, key_generation=None, title_id=None, 
              title_version=None, prodkeys=None)
```

### TIK
```
tik.get_titlekey(tik)
```