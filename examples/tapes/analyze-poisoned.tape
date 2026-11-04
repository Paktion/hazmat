# Live recording of a full Hazmat run on the poisoned test sample.
#   vhs examples/tapes/analyze-poisoned.tape
Output examples/hazmat-analyze-stealer_sim_poisoned.mp4
Output examples/hazmat-analyze-stealer_sim_poisoned.txt
Set Shell "bash"
Set FontSize 15
Set Width 1800
Set Height 1000
Set Padding 20
Set TypingSpeed 25ms
Hide
Type "source .venv/bin/activate && export PS1='$ ' && clear" Enter
Show
Type "hazmat analyze testdata/bin/stealer_sim_poisoned.exe --backend docker --run-root examples/runs" Sleep 500ms Enter
Wait+Screen@15m /Report: /
Sleep 4s
