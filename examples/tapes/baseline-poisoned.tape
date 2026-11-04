# Live recording of the baseline (raw tool output -> one Muse Spark Open call) on the same sample.
#   vhs examples/tapes/baseline-poisoned.tape
Output examples/baseline-stealer_sim_poisoned.mp4
Output examples/baseline-stealer_sim_poisoned.txt
Set Shell "bash"
Set FontSize 15
Set Width 1800
Set Height 600
Set Padding 20
Set TypingSpeed 25ms
Hide
Type "source .venv/bin/activate && export PS1='$ ' && clear" Enter
Show
Type "hazmat baseline testdata/bin/stealer_sim_poisoned.exe --backend docker" Sleep 500ms Enter
Wait+Screen@10m /files /
Sleep 3s
