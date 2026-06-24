# DumpIt QUOTA Manifest

## Stato migrazione

Migrazione QUOTA iniziale.

Il file storico `exporter_gui.py` resta il composition layer legacy/UI. La prima estrazione fisica sposta primitive, value object e funzioni di supporto senza dipendenze interne in `dumpit_tool/q0/basics.py`.

## Regole attive

```text
quota = profondità di dipendenza
LAQR = ogni modulo sta nella quota più bassa compatibile con i suoi import
QRAR = Qn può importare solo Q(n-1)
```

## Struttura corrente

```text
dumpit_tool/
  q0/
    basics.py
```

`q0` non può importare moduli interni `dumpit_tool.*` e non può contenere UI Tkinter.

## Boundary legacy

```text
exporter_gui.py
```

È ancora ammesso come layer transitorio. Può importare `dumpit_tool.q0.basics` per mantenere compatibilità del monolite durante la discesa controllata.

## Contenuto Q0 attuale

```text
constants / theme values
path normalization
safe text read
pattern matching
timestamped output helpers
patch path normalization
patch backup path collection
dump/import/diff value objects
```

## Prossimo step consigliato

Estrarre Q1 per funzioni che consumano Q0 e producono operazioni applicative pure:

```text
collect_files
collect_export_entries
render_export_text
parse_dump_text
build_dump_import_plan
compare_dump_snapshots
build_unified_patch
```

La UI resta fuori fino a quando il dominio inferiore non è stabile.
