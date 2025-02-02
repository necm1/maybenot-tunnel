use enum_map::EnumMap;
use log::info;
use maybenot::{event::Event, state::State, state::Trans, Framework, Machine};
use rand::{rngs::StdRng, SeedableRng};
use std::{sync::Arc, time::Instant};
use tokio::sync::Mutex; // EnumMap importieren

pub type MaybenotFramework = Arc<Mutex<Framework<&'static [Machine], StdRng>>>;

pub fn init_maybenot() -> MaybenotFramework {
    let rng = StdRng::from_entropy();

    let empty_transitions: EnumMap<Event, Vec<Trans>> = Default::default();

    let machine_vec = vec![Machine::new(
        0,                                   // Machine-ID oder Initialwert
        0.5,                                 // Wahrscheinlichkeitswert
        0,                                   // Counter oder andere ID
        0.8,                                 // Weiterer Wahrscheinlichkeitswert
        vec![State::new(empty_transitions)], // Hier wird der richtige Wert übergeben!
    )
    .expect("❌ Fehler beim Erstellen der Machine")];

    // `Box::leak`, um Maschinen lebenslang verfügbar zu machen
    let machine_static: &'static [Machine] = Box::leak(Box::new(machine_vec));

    let framework = Framework::new(machine_static, 0.5, 0.8, Instant::now(), rng)
        .expect("❌ Fehler beim Initialisieren von Maybenot!");

    info!("✅ Maybenot-Framework initialisiert.");
    Arc::new(Mutex::new(framework))
}
