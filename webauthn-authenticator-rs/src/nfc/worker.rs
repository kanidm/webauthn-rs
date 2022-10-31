// Need to push all the PC/SC operations into a worker thread, so that these
// operations stay on a single thread, and don't pass structures around.

use std::{
    collections::BTreeMap,
    ffi::CString,
    sync::mpsc::{Receiver, Sender, TryRecvError, RecvTimeoutError, channel}, time::Duration, thread::{self, JoinHandle},
};

use pcsc::{Card, Context, Protocols, ReaderState, ShareMode, State, MAX_BUFFER_SIZE_EXTENDED, Scope};

pub struct PcscWorker {
    ctx: Context,
    receiver: Receiver<WorkerCmd>,
    sender: Sender<WorkerMsg>,
    reader_states: Vec<ReaderState>,
    connections: BTreeMap<String, Card>,
}

pub enum WorkerCmd {
    Connect(String),
    Transmit(String, Vec<u8>),
    Disconnect(String),
    ListReaders,
}

pub enum WorkerMsg {
    ReaderChange(String, State, Vec<u8>),
    Receive(String, Vec<u8>),
    Error(pcsc::Error),
    ReaderList(Vec<(String, State, Vec<u8>)>),
}

impl PcscWorker {
    pub fn new() -> (Receiver<WorkerMsg>, Sender<WorkerCmd>, JoinHandle<()>) {
        let (tx1, rx1) = channel();
        let (tx2, rx2) = channel();
        let ctx = Context::establish(Scope::User).unwrap();

        let handle = thread::spawn(move || {
            let mut worker = PcscWorker {
                ctx,
                receiver: rx2,
                sender: tx1,
                reader_states: vec![],
                connections: BTreeMap::new(),
            };

            while worker.handle_pending_events() {
                thread::sleep(Duration::from_millis(100));
            }
        });

        (rx1, tx2, handle)
    }

    fn get_reader_states(&mut self) -> Result<(), pcsc::Error> {
        // Remove all disconnected readers
        let mut i = 0;
        while i < self.reader_states.len() {
            if self.reader_states[i].event_state().contains(State::IGNORE) {
                self.reader_states.remove(i);
            } else {
                self.reader_states[i].sync_current_state();
                i += 1;
            }
        }

        // Get a list of readers right now
        let readers = self.ctx.list_readers_owned()?;

        // Add any new readers to the list
        for reader_name in readers {
            if self
                .reader_states
                .iter()
                .find(|s| s.name() == reader_name.as_c_str())
                .is_none()
            {
                // New reader
                self.reader_states
                    .push(ReaderState::new(reader_name, State::UNAWARE));
            }
        }

        // Update all reader states
        self.ctx.get_status_change(None, &mut self.reader_states)?;

        // Now broadcast any changes
        let new_states = vec![];
        for state in &self.reader_states {
            // if state.event_state().contains(State::CHANGED) {
            // }
            if let Ok(name) = state.name().to_str() {
                let name = name.to_string();
                let atr = state.atr().to_vec();

                // self.send(WorkerMsg::ReaderChange(name, state.event_state(), atr));
                new_states.push((name, state.event_state(), atr));
            }

        }
        self.send(WorkerMsg::ReaderList(new_states));

        Ok(())
    }

    fn send(&self, msg: WorkerMsg) {
        self.sender.send(msg).ok();
    }

    fn handle_cmd(&mut self, cmd: WorkerCmd) -> Result<(), pcsc::Error> {
        use WorkerCmd::*;
        match cmd {
            Connect(reader) => {
                let reader_c = CString::new(reader.as_str()).unwrap();
                let card =
                    self.ctx
                        .connect(reader_c.as_c_str(), ShareMode::Shared, Protocols::ANY)?;

                // add to connections list
                self.connections.insert(reader, card);
            }
            Transmit(reader, apdu) => {
                if let Some(card) = self.connections.get(&reader) {
                    let mut resp = vec![0; MAX_BUFFER_SIZE_EXTENDED];

                    let rapdu = card.transmit(apdu.as_slice(), &mut resp)?;

                    self.send(WorkerMsg::Receive(reader, rapdu.to_vec()));
                } else {
                    self.send(WorkerMsg::Error(pcsc::Error::UnknownReader));
                }
            }
            Disconnect(reader) => {
                self.connections.remove(&reader);
            },
            ListReaders => {
                self.get_reader_states();
            },
        }
        Ok(())
    }

    fn handle_pending_events(&mut self) -> bool {
        // if let Err(e) = self.refresh_reader_state() {
        //     self.send(WorkerMsg::Error(e));
        // }

        loop {
            let r = self.receiver.recv_timeout(Duration::from_millis(100));
            match r {
                Ok(cmd) => self.handle_cmd(cmd).map_err(|e| {
                    self.send(WorkerMsg::Error(e));
                }),
                Err(RecvTimeoutError::Disconnected) => return false,
                Err(RecvTimeoutError::Timeout) => return true,
            };
        }
    }
}
