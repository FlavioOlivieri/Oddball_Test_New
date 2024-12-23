import React, { useState } from 'react';
import { Toolbar } from 'primereact/toolbar';
import CardSettings from './CardSettings';
import '../css/Toolbar.css';
import CardProfile from './CardProfile';
import ImageSequence from './ImageSequence';
import { Button } from 'primereact/button';

export default function Bar() {
    const [showCard, setShowCard] = useState(null);
    const [startImageSequence, setStartImageSequence] = useState(false);
    const [reactionTime, setReactionTime] = useState(0);
    const [flagRare, setFlagRare] = useState(0);
    const [imageSequenceComplete, setImageSequenceComplete] = useState(false);

    const handlePlayClick = () => {
        setStartImageSequence(false);
        setTimeout(() => {
            setShowCard('play');
            setStartImageSequence(true);
        }, 10); // Breve ritardo per permettere il reset
    };

    const handleHomeClick = () => {
        // Resetta lo stato della card visualizzata e interrompe il test
        setShowCard(null);
        setStartImageSequence(false);
    };

    const handleDataFromImageSequence = (data) => {
        console.log("Dati ricevuti da ImageSequence:", data);
        setReactionTime(data.reactionTime);
        setFlagRare(data.flagRare);
        setImageSequenceComplete(true);
    };


    const centerContent = (
        <div className="center">
            <button className='bar-button' onClick={() => setShowCard((prev) => prev === 'settings' ? null : 'settings')}>
                <i className="pi pi-cog"></i>
            </button>

            <button className='bar-button' onClick={handlePlayClick}>
                <i className="pi pi-play-circle"></i>
            </button>

            <button className='bar-button' onClick={() => setShowCard((prev) => prev === 'profile' ? null : 'profile')}>
                <i className="pi pi-user"></i>
            </button>
        </div>
    );

    return (
        <>
            <div className="div-bar">
                <Toolbar center={centerContent} className="bar" />
                {showCard === 'settings' && <CardSettings />}
                {showCard === 'play' && (
                    <ImageSequence
                        onStart={startImageSequence}
                        onComplete={handleDataFromImageSequence}
                    />
                )}
                {showCard === 'profile' && (
                    <CardProfile reactionTime={reactionTime} flagRare={flagRare} />
                )}
            </div>
            <Button className="button-home" icon="pi pi-home" onClick={handleHomeClick} />
        </>
    );
}
